/* SPDX-License-Identifier: MIT */
/*
 * Test that IORING_CQE_F_BUF_MORE survives bundle recv retries with
 * incremental provided buffer rings.
 *
 * Bug: io_recv_finish() merges CQE flags across bundle retry iterations
 * using:
 *
 *   cflags = req->cqe.flags | (cflags & CQE_F_MASK);
 *
 * CQE_F_MASK did not include IORING_CQE_F_BUF_MORE, so the flag was
 * silently dropped on the final retry iteration when a buffer entry was
 * partially consumed.  Userspace would then wrongfully advance its
 * buffer ring head past an entry the kernel still considers in use.
 *
 * To trigger the bundle retry path reliably:
 *
 * 1. Use sqe->len = 0 so that mshot_len = 0 and IORING_RECV_MSHOT_CAP
 *    is never set (it would prevent retries via IORING_RECV_NO_RETRY).
 *
 * 2. Use multiple small buffer entries in an incremental buffer ring.
 *    On multishot continuation calls, msg_inq from the previous recv
 *    limits max_len, which provides fewer entries than available, so
 *    REQ_F_BL_EMPTY is not set.
 *
 * 3. Use a sender thread that fills the socket and continues sending
 *    so that after a recv that consumes the limited buffer, msg_inq > 1
 *    (more data arrived), triggering the bundle retry.
 *
 * When the retry's first iteration fully consumes one or more entries
 * and the second iteration partially consumes the next, BUF_MORE must
 * be set.  On the buggy kernel, the merge drops it.
 *
 * Fixed by adding IORING_CQE_F_BUF_MORE to CQE_F_MASK.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "liburing.h"
#include "helpers.h"

/*
 * Multiple small entries: the kernel will provide a subset when
 * max_len < total capacity, leaving entries for the retry.
 */
#define NR_BUFS		256
#define BUF_ENTRY_SIZE	4096
#define TOTAL_BUF_SIZE	(NR_BUFS * BUF_ENTRY_SIZE)	/* 1 MB */
#define BUF_BGID	1
#define BUF_MASK	(NR_BUFS - 1)

/*
 * Total data to send.  Must be less than TOTAL_BUF_SIZE so the buffer
 * ring is never fully consumed.
 */
#define TOTAL_SEND	(512 * 1024)

/*
 * Intentionally NOT a multiple of BUF_ENTRY_SIZE so that the data
 * in the TCP receive buffer is not aligned to entry boundaries.
 * This ensures msg_inq values that cause partial-entry consumption.
 */
#define SEND_CHUNK	3000

static int no_bundle_inc;

struct send_data {
	int fd;
	int total;
	pthread_barrier_t barrier;
};

static void *sender_fn(void *arg)
{
	struct send_data *sd = arg;
	unsigned char *data;
	int sent = 0;

	data = malloc(SEND_CHUNK);
	if (!data)
		return (void *)(intptr_t)1;

	pthread_barrier_wait(&sd->barrier);

	while (sent < sd->total) {
		int chunk = sd->total - sent;
		int ret;

		if (chunk > SEND_CHUNK)
			chunk = SEND_CHUNK;

		/* Fill with pattern for verification */
		for (int i = 0; i < chunk; i++)
			data[i] = (sent + i) & 0xff;

		ret = send(sd->fd, data, chunk, 0);
		if (ret < 0) {
			if (errno == EPIPE)
				break;
			perror("send");
			free(data);
			return (void *)(intptr_t)1;
		}
		sent += ret;
	}

	/* Signal EOF */
	shutdown(sd->fd, SHUT_WR);
	free(data);
	return NULL;
}

static int arm_recv(struct io_uring *ring, int fd)
{
	struct io_uring_sqe *sqe;
	int ret;

	sqe = io_uring_get_sqe(ring);
	/*
	 * sqe->len = 0: critical for avoiding MSHOT_CAP which would
	 * block the retry path via IORING_RECV_NO_RETRY.
	 */
	io_uring_prep_recv_multishot(sqe, fd, NULL, 0, 0);
	sqe->ioprio |= IORING_RECVSEND_BUNDLE;
	sqe->buf_group = BUF_BGID;
	sqe->flags |= IOSQE_BUFFER_SELECT;
	sqe->user_data = 1;

	ret = io_uring_submit(ring);
	if (ret != 1) {
		fprintf(stderr, "submit: %d\n", ret);
		return 1;
	}
	return 0;
}

static int test(void)
{
	struct io_uring_buf_ring *br;
	struct io_uring_params p = { };
	struct io_uring ring;
	struct send_data sd;
	pthread_t sender;
	unsigned char *buf;
	int fds[2];
	int ret, val;
	int recv_bytes = 0;
	int buf_more_missing = 0;
	int partial_cqes = 0;
	void *tret;

	p.cq_entries = 4096;
	p.flags = IORING_SETUP_CQSIZE;
	ret = io_uring_queue_init_params(16, &ring, &p);
	if (ret) {
		fprintf(stderr, "ring init: %d\n", ret);
		return T_EXIT_FAIL;
	}

	if (!(p.features & IORING_FEAT_RECVSEND_BUNDLE)) {
		io_uring_queue_exit(&ring);
		return T_EXIT_SKIP;
	}

	if (posix_memalign((void **)&buf, 4096, TOTAL_BUF_SIZE)) {
		io_uring_queue_exit(&ring);
		return T_EXIT_FAIL;
	}
	memset(buf, 0, TOTAL_BUF_SIZE);

	br = io_uring_setup_buf_ring(&ring, NR_BUFS, BUF_BGID,
				     IOU_PBUF_RING_INC, &ret);
	if (!br) {
		free(buf);
		io_uring_queue_exit(&ring);
		if (ret == -EINVAL) {
			no_bundle_inc = 1;
			return T_EXIT_SKIP;
		}
		fprintf(stderr, "buf ring setup: %d\n", ret);
		return T_EXIT_FAIL;
	}

	for (int i = 0; i < NR_BUFS; i++) {
		io_uring_buf_ring_add(br, buf + i * BUF_ENTRY_SIZE,
				      BUF_ENTRY_SIZE, i, BUF_MASK, i);
	}
	io_uring_buf_ring_advance(br, NR_BUFS);

	ret = t_create_socket_pair(fds, true);
	if (ret) {
		fprintf(stderr, "socket pair: %d\n", ret);
		goto fail;
	}

	val = 1;
	setsockopt(fds[1], IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));

	/* Start sender thread */
	sd.fd = fds[1];
	sd.total = TOTAL_SEND;
	pthread_barrier_init(&sd.barrier, NULL, 2);

	ret = pthread_create(&sender, NULL, sender_fn, &sd);
	if (ret) {
		fprintf(stderr, "pthread_create: %d\n", ret);
		goto fail;
	}

	/* Arm recv and let sender start */
	if (arm_recv(&ring, fds[0]))
		goto fail;
	pthread_barrier_wait(&sd.barrier);

	/* Collect completions */
	while (recv_bytes < TOTAL_SEND) {
		struct io_uring_cqe *cqe;
		struct __kernel_timespec ts = { .tv_sec = 10, };

		ret = io_uring_wait_cqe_timeout(&ring, &cqe, &ts);
		if (ret) {
			fprintf(stderr, "wait: %d (recv'd %d/%d)\n",
				ret, recv_bytes, TOTAL_SEND);
			goto join_fail;
		}

		if (cqe->res == -ENOBUFS) {
			io_uring_cqe_seen(&ring, cqe);
			continue;
		}
		if (cqe->res == -EINVAL) {
			io_uring_cqe_seen(&ring, cqe);
			no_bundle_inc = 1;
			pthread_join(sender, NULL);
			close(fds[0]);
			close(fds[1]);
			free(buf);
			io_uring_queue_exit(&ring);
			return T_EXIT_SKIP;
		}
		if (cqe->res <= 0) {
			if (cqe->res == 0 && recv_bytes >= TOTAL_SEND) {
				io_uring_cqe_seen(&ring, cqe);
				break;
			}
			fprintf(stderr, "recv error: res=%d recv=%d\n",
				cqe->res, recv_bytes);
			io_uring_cqe_seen(&ring, cqe);
			goto join_fail;
		}

		if (!(cqe->flags & IORING_CQE_F_BUFFER)) {
			fprintf(stderr, "IORING_CQE_F_BUFFER not set\n");
			io_uring_cqe_seen(&ring, cqe);
			goto join_fail;
		}

		/*
		 * If the total bytes consumed so far is not a multiple of
		 * BUF_ENTRY_SIZE, the last buffer entry was only partially
		 * used and BUF_MORE must be set.  We check the cumulative
		 * total (not just cqe->res) because a previous CQE may
		 * have partially consumed an entry that this CQE finishes.
		 *
		 * On a buggy kernel where the bundle retry drops BUF_MORE
		 * from the merge, this check catches the regression.
		 *
		 * Note: only check when the buffer ring hasn't been
		 * fully consumed (recv_bytes + cqe->res < TOTAL_BUF_SIZE).
		 */
		if (((recv_bytes + cqe->res) % BUF_ENTRY_SIZE) != 0 &&
		    (recv_bytes + cqe->res) < TOTAL_BUF_SIZE) {
			partial_cqes++;
			if (!(cqe->flags & IORING_CQE_F_BUF_MORE)) {
				fprintf(stderr,
					"FAIL: BUF_MORE not set after partial "
					"entry consumption!\n"
					"  cqe->res=%d flags=0x%x "
					"recv_bytes=%d\n",
					cqe->res, cqe->flags, recv_bytes);
				buf_more_missing = 1;
			}
		}

		recv_bytes += cqe->res;

		if (!(cqe->flags & IORING_CQE_F_MORE) &&
		    recv_bytes < TOTAL_SEND) {
			io_uring_cqe_seen(&ring, cqe);
			if (arm_recv(&ring, fds[0]))
				goto join_fail;
			continue;
		}

		io_uring_cqe_seen(&ring, cqe);
	}

	pthread_join(sender, &tret);

	if (tret) {
		fprintf(stderr, "sender thread failed\n");
		goto fail;
	}

	if (buf_more_missing)
		goto fail;

	if (!partial_cqes)
		fprintf(stderr, "info: no partial-entry CQEs seen, "
			"retry path may not have been exercised\n");

	if (recv_bytes < TOTAL_SEND) {
		fprintf(stderr, "short recv: got %d, wanted %d\n",
			recv_bytes, TOTAL_SEND);
		goto fail;
	}

	/* Verify data integrity */
	for (int i = 0; i < recv_bytes; i++) {
		if (buf[i] != (i & 0xff)) {
			fprintf(stderr, "data mismatch at %d: got %d want %d\n",
				i, buf[i], i & 0xff);
			goto fail;
		}
	}

	close(fds[0]);
	close(fds[1]);
	free(buf);
	io_uring_queue_exit(&ring);
	return T_EXIT_PASS;

join_fail:
	pthread_join(sender, NULL);
fail:
	close(fds[0]);
	close(fds[1]);
	free(buf);
	io_uring_queue_exit(&ring);
	return T_EXIT_FAIL;
}

int main(int argc, char *argv[])
{
	if (argc > 1)
		return T_EXIT_SKIP;

	return test();
}
