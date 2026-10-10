/* End-to-end PolyStore io_uring test. Use a NEW /mnt/polystore/<name> path.
 * Creates the file exclusively and keeps it for inspection. No raw device I/O.
 * Usage: LD_PRELOAD=... ./io_uring_smoke /mnt/polystore/<name> buffered|direct
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/io_uring.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#define QD 32
#define BS 4096
#define EXTENT (2ULL * 1024 * 1024)
#define REQUIRE(x) do { if (!(x)) { fprintf(stderr, "FAIL line %d: %s (errno=%d)\n", __LINE__, #x, errno); exit(1); } } while (0)
struct ring {
    int fd;
    struct io_uring_params p;
    void *sq, *cq;
    struct io_uring_sqe *sqes;
    size_t sqlen, cqlen, sqelen;
    unsigned *tail, *mask, *array, *cqhead, *cqtail, *cqmask;
    struct io_uring_cqe *cqes;
};
static void ring_init(struct ring *r) {
    memset(r, 0, sizeof(*r));
    r->fd = syscall(SYS_io_uring_setup, QD, &r->p);
    REQUIRE(r->fd >= 0);
    r->sqlen = r->p.sq_off.array + r->p.sq_entries * sizeof(unsigned);
    r->cqlen = r->p.cq_off.cqes + r->p.cq_entries * sizeof(struct io_uring_cqe);
    if ((r->p.features & IORING_FEAT_SINGLE_MMAP) && r->cqlen > r->sqlen)
        r->sqlen = r->cqlen;
    r->sq = mmap(NULL, r->sqlen, PROT_READ | PROT_WRITE, MAP_SHARED, r->fd, IORING_OFF_SQ_RING);
    REQUIRE(r->sq != MAP_FAILED);
    r->cq = (r->p.features & IORING_FEAT_SINGLE_MMAP) ? r->sq :
        mmap(NULL, r->cqlen, PROT_READ | PROT_WRITE, MAP_SHARED, r->fd, IORING_OFF_CQ_RING);
    REQUIRE(r->cq != MAP_FAILED);
    r->sqelen = r->p.sq_entries * sizeof(struct io_uring_sqe);
    r->sqes = mmap(NULL, r->sqelen, PROT_READ | PROT_WRITE, MAP_SHARED, r->fd, IORING_OFF_SQES);
    REQUIRE(r->sqes != MAP_FAILED);
    r->tail = (void *)((char *)r->sq + r->p.sq_off.tail);
    r->mask = (void *)((char *)r->sq + r->p.sq_off.ring_mask);
    r->array = (void *)((char *)r->sq + r->p.sq_off.array);
    r->cqhead = (void *)((char *)r->cq + r->p.cq_off.head);
    r->cqtail = (void *)((char *)r->cq + r->p.cq_off.tail);
    r->cqmask = (void *)((char *)r->cq + r->p.cq_off.ring_mask);
    r->cqes = (void *)((char *)r->cq + r->p.cq_off.cqes);
}
static void queue(struct ring *r, unsigned op, int fd, void *buf,
                  unsigned len, uint64_t off, unsigned tag) {
    unsigned tail = __atomic_load_n(r->tail, __ATOMIC_RELAXED);
    unsigned slot = tail & *r->mask;
    struct io_uring_sqe *sqe = &r->sqes[slot];
    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = op; sqe->fd = fd; sqe->off = off;
    sqe->addr = (uintptr_t)buf; sqe->len = len; sqe->user_data = tag;
    r->array[slot] = slot;
    __atomic_store_n(r->tail, tail + 1, __ATOMIC_RELEASE);
}
static void complete(struct ring *r, unsigned count, int expected) {
    long nr;
    do { nr = syscall(SYS_io_uring_enter, r->fd, count, 0, 0, NULL, 0); }
    while (nr < 0 && errno == EINTR);
    REQUIRE(nr == count);
    unsigned head = __atomic_load_n(r->cqhead, __ATOMIC_RELAXED);
    while (__atomic_load_n(r->cqtail, __ATOMIC_ACQUIRE) - head < count) {
        nr = syscall(SYS_io_uring_enter, r->fd, 0, count, IORING_ENTER_GETEVENTS, NULL, 0);
        REQUIRE(nr >= 0 || errno == EINTR);
    }
    uint64_t seen = 0;
    for (unsigned i = 0; i < count; ++i) {
        struct io_uring_cqe *cqe = &r->cqes[(head + i) & *r->cqmask];
        if (cqe->res != expected)
            fprintf(stderr, "CQE tag=%llu res=%d expected=%d\n", (unsigned long long)cqe->user_data, cqe->res, expected);
        REQUIRE(cqe->res == expected);
        REQUIRE(cqe->user_data < count);
        REQUIRE(!(seen & (1ULL << cqe->user_data)));
        seen |= 1ULL << cqe->user_data;
    }
    REQUIRE(seen == ((1ULL << count) - 1));
    __atomic_store_n(r->cqhead, head + count, __ATOMIC_RELEASE);
}
static void one(struct ring *r, unsigned op, int fd, void *buf, unsigned len,
                uint64_t off, int expected) {
    queue(r, op, fd, buf, len, off, 0); complete(r, 1, expected);
}
static void pattern(unsigned char *p, size_t n, unsigned seed) {
    for (size_t i = 0; i < n; ++i) p[i] = (unsigned char)((i * 37 + seed * 61 + (i >> 8)) & 255);
}
int main(int argc, char **argv) {
    REQUIRE(argc == 3);
    REQUIRE(!strncmp(argv[1], "/mnt/polystore/", 15));
    int direct = !strcmp(argv[2], "direct");
    REQUIRE(direct || !strcmp(argv[2], "buffered"));
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("BEGIN %s %s QD=%d\n", argv[1], argv[2], QD);
    struct ring r;
    ring_init(&r);
    int flags = O_CREAT | O_EXCL | O_RDWR | (direct ? O_DIRECT : 0);
    int fd = open(argv[1], flags, 0600);
    REQUIRE(fd >= 0 && (fd & 0x1000000));
    int fastfd = fd & 0xfff, slowfd = (fd >> 12) & 0xfff;
    REQUIRE((fcntl(fastfd, F_GETFL) & O_DIRECT) == (direct ? O_DIRECT : 0));
    REQUIRE((fcntl(slowfd, F_GETFL) & O_DIRECT) == (direct ? O_DIRECT : 0));
    unsigned char *w, *b;
    REQUIRE(!posix_memalign((void **)&w, BS, QD * BS));
    REQUIRE(!posix_memalign((void **)&b, BS, QD * BS));
    for (unsigned round = 0; round < 4; ++round) {
        for (unsigned i = 0; i < QD; ++i) {
            pattern(w + i * BS, BS, round * QD + i);
            queue(&r, IORING_OP_WRITE, fd, w + i * BS, BS, i * EXTENT + round * BS, i);
        }
        complete(&r, QD, BS);
        memset(b, 0, QD * BS);
        for (unsigned i = 0; i < QD; ++i)
            queue(&r, IORING_OP_READ, fd, b + i * BS, BS, i * EXTENT + round * BS, i);
        complete(&r, QD, BS);
        REQUIRE(!memcmp(w, b, QD * BS));
    }
    puts("PASS QD32: 128 writes + 128 reads across 32 extents, byte comparison");
    pattern(w, 2 * BS, 200);
    struct iovec wiov[2] = {{w, BS}, {w + BS, BS}};
    struct iovec riov[2] = {{b, BS}, {b + BS, BS}};
    one(&r, IORING_OP_WRITEV, fd, wiov, 2, 8 * BS, 2 * BS);
    memset(b, 0, 2 * BS);
    one(&r, IORING_OP_READV, fd, riov, 2, 8 * BS, 2 * BS);
    REQUIRE(!memcmp(w, b, 2 * BS));
    one(&r, IORING_OP_WRITEV, fd, wiov, 2, EXTENT - BS, BS);
    REQUIRE(wiov[0].iov_len == BS && wiov[1].iov_len == BS);
    one(&r, IORING_OP_WRITEV, fd, wiov + 1, 1, EXTENT, BS);
    memset(b, 0xa5, 2 * BS);
    one(&r, IORING_OP_READV, fd, riov, 2, EXTENT - BS, BS);
    REQUIRE(!memcmp(w, b, BS));
    for (unsigned i = BS; i < 2 * BS; ++i) REQUIRE(b[i] == 0xa5);
    REQUIRE(riov[0].iov_len == BS && riov[1].iov_len == BS);
    one(&r, IORING_OP_READV, fd, riov + 1, 1, EXTENT, BS);
    REQUIRE(!memcmp(w, b, 2 * BS));
    puts("PASS READV/WRITEV: regular, extent boundary, short completion and retry");
    struct iovec fixed = {w, BS};
    REQUIRE(!syscall(SYS_io_uring_register, r.fd, IORING_REGISTER_BUFFERS, &fixed, 1));
    pattern(w, BS, 201); memcpy(b, w, BS);
    one(&r, IORING_OP_WRITE_FIXED, fd, w, BS, QD * EXTENT, BS);
    memset(w, 0, BS);
    one(&r, IORING_OP_READ_FIXED, fd, w, BS, QD * EXTENT, BS);
    REQUIRE(!memcmp(w, b, BS));
    REQUIRE(!syscall(SYS_io_uring_register, r.fd, IORING_UNREGISTER_BUFFERS, NULL, 0));
    puts("PASS registered buffer WRITE_FIXED/READ_FIXED");
    one(&r, IORING_OP_WRITE, fd, w, 0, (QD + 1) * EXTENT, 0);
    one(&r, IORING_OP_READ, fd, w, BS, QD * EXTENT + BS, 0);
    REQUIRE(!fsync(fd));
    REQUIRE(!close(fd));
    fd = open(argv[1], O_RDWR | (direct ? O_DIRECT : 0));
    REQUIRE(fd >= 0 && (fd & 0x1000000));
    memset(w, 0, BS);
    one(&r, IORING_OP_READ, fd, w, BS, QD * EXTENT, BS);
    REQUIRE(!memcmp(w, b, BS));
    REQUIRE(!close(fd));
    puts("PASS zero length, EOF, fsync and close/reopen readback");
    munmap(r.sqes, r.sqelen);
    if (r.cq != r.sq) munmap(r.cq, r.cqlen);
    munmap(r.sq, r.sqlen); close(r.fd); free(w); free(b);
    puts("POLYSTORE_TEST_PASS");
    return 0;
}
