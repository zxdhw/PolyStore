/*
 * Transparent routing for io_uring requests that reference PolyStore files.
 * The kernel must see one of the real backing descriptors, never PolyStore's
 * synthetic descriptor. Requests crossing a placement extent are shortened;
 * applications can submit the remainder after receiving the short completion.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/io_uring.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/uio.h>

#include "libsyscall_intercept_hook_point.h"
#include "polystore.h"

#define POLYSTORE_URING_MAX_RINGS 64

struct polystore_uring_ring {
        int fd;
        int active;
        struct io_uring_params params;
        void *sq_ring;
        struct io_uring_sqe *sqes;
        unsigned *sq_head;
        unsigned *sq_tail;
        unsigned *sq_mask;
        unsigned *sq_array;
};

struct polystore_uring_backup {
        struct io_uring_sqe *sqe;
        struct poly_file *file;
        struct poly_inode *inode;
        struct it_node_entry *entry;
        int fd;
        int is_write;
        uint64_t off;
        uint64_t logical_end;
        uint64_t addr;
        uint32_t len;
        uint32_t bytes;
        struct iovec *iov;
};

static struct polystore_uring_ring uring_rings[POLYSTORE_URING_MAX_RINGS];
static pthread_mutex_t uring_submit_locks[POLYSTORE_URING_MAX_RINGS];
static pthread_mutex_t uring_rings_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t uring_locks_once = PTHREAD_ONCE_INIT;

static void uring_locks_initialize(void) {
        int i;
        for (i = 0; i < POLYSTORE_URING_MAX_RINGS; ++i)
                pthread_mutex_init(&uring_submit_locks[i], NULL);
}

static struct polystore_uring_ring *uring_ring_find(int fd) {
        int i;

        for (i = 0; i < POLYSTORE_URING_MAX_RINGS; ++i) {
                if (uring_rings[i].active && uring_rings[i].fd == fd)
                        return &uring_rings[i];
        }
        return NULL;
}

static int uring_ring_store(int fd, const struct io_uring_params *params) {
        int i, slot = -1;

        pthread_once(&uring_locks_once, uring_locks_initialize);
        pthread_mutex_lock(&uring_rings_lock);
        for (i = 0; i < POLYSTORE_URING_MAX_RINGS; ++i) {
                if (uring_rings[i].active && uring_rings[i].fd == fd) {
                        slot = i;
                        break;
                }
                if (!uring_rings[i].active && slot < 0)
                        slot = i;
        }
        if (slot >= 0) {
                memset(&uring_rings[slot], 0, sizeof(uring_rings[slot]));
                uring_rings[slot].fd = fd;
                uring_rings[slot].active = 1;
                uring_rings[slot].params = *params;
        }
        pthread_mutex_unlock(&uring_rings_lock);
        return slot >= 0 ? 0 : -ENOSPC;
}

static int uring_extent_create(struct poly_file *file, off_t logical_offset,
                               struct it_node_entry **out) {
        struct poly_inode *inode = file->inode;
        struct it_node_entry *entry;
        int polyfd = file->polyfd;
        int physical_fd;
        int index_no;
        off_t logical_start;
        off_t physical_end;
        off_t physical_start;
        int placement;

        if (!tls_task_ctx.task_ctx)
                return -EIO;

        placement = tls_task_ctx.task_ctx->placement;
        if (placement != BLK_PLACEMENT_FAST &&
            placement != BLK_PLACEMENT_SLOW)
                return -EIO;

        logical_start = logical_offset & POLY_INDEX_NODE_SIZE_MASK;
        if (logical_start > INT64_MAX - (POLY_INDEX_NODE_SIZE - 1))
                return -EFBIG;
        physical_fd = placement == BLK_PLACEMENT_FAST ?
                      POLYSTORE_FAST_FD(polyfd) :
                      POLYSTORE_SLOW_FD(polyfd);
        physical_end = syscall_no_intercept(SYS_lseek, physical_fd, 0,
                                            SEEK_END);
        if (physical_end < 0)
                return (int)physical_end;
        if (physical_end > INT64_MAX - (POLY_INDEX_NODE_SIZE - 1))
                return -EFBIG;
        physical_start = (physical_end + POLY_INDEX_NODE_SIZE - 1) &
                         POLY_INDEX_NODE_SIZE_MASK;
        if (physical_start > INT64_MAX - POLY_INDEX_NODE_SIZE)
                return -EFBIG;
        {
                long ret = syscall_no_intercept(SYS_ftruncate, physical_fd,
                                physical_start + POLY_INDEX_NODE_SIZE);
                if (ret < 0)
                        return (int)ret;
        }

        entry = polystore_index_entry_allocate(inode);
        if (!entry)
                return -ENOMEM;
        index_no = entry->idx_no;
        memset(entry, 0, sizeof(*entry));
        entry->idx_no = index_no;
        entry->it.start = logical_start;
        entry->it.last = logical_start + POLY_INDEX_NODE_SIZE - 1;
        entry->size = 0;
        entry->inode = inode;
        entry->ref_count = 1;
        entry->placement = placement;
        entry->offset = physical_start;
        pthread_mutex_init(&entry->lock, NULL);

        polystore_index_insert(inode, entry);
        inode->placement = BLK_PLACEMENT_BOTH;
        *out = entry;
        return 0;
}

/* Returns 1 after translating a supported PolyStore SQE, 0 otherwise. */
static int polystore_uring_translate(struct io_uring_sqe *sqe,
                                     struct polystore_uring_backup *backup) {
        struct poly_file *file;
        struct poly_inode *inode;
        struct it_node_entry *entry = NULL;
        uint64_t logical_offset;
        uint64_t remaining;
        uint64_t request_size;
        uint64_t physical_offset;
        uint64_t i;
        int is_write;
        int physical_fd;
        uint32_t total_len;
        int is_vector;

        if (sqe->flags & IOSQE_FIXED_FILE)
                return 0;
        if (sqe->opcode != IORING_OP_READ &&
            sqe->opcode != IORING_OP_WRITE &&
            sqe->opcode != IORING_OP_READV &&
            sqe->opcode != IORING_OP_WRITEV &&
            sqe->opcode != IORING_OP_READ_FIXED &&
            sqe->opcode != IORING_OP_WRITE_FIXED)
                return 0;
        if (!POLYSTORE_FD_CHECK(sqe->fd))
                return 0;

        file = polystore_file_find(sqe->fd);
        if (!file || !file->inode || sqe->off == (uint64_t)-1)
                return 0;

        is_write = sqe->opcode == IORING_OP_WRITE ||
                   sqe->opcode == IORING_OP_WRITEV ||
                   sqe->opcode == IORING_OP_WRITE_FIXED;
        is_vector = sqe->opcode == IORING_OP_READV ||
                    sqe->opcode == IORING_OP_WRITEV;
        total_len = sqe->len;
        if (is_vector) {
                struct iovec *iov = (struct iovec *)(uintptr_t)sqe->addr;
                uint64_t sum = 0;

                if (!iov || sqe->len > IOV_MAX)
                        return 0;
                for (i = 0; i < sqe->len; ++i) {
                        sum += iov[i].iov_len;
                        if (sum > UINT32_MAX)
                                return 0;
                }
                total_len = (uint32_t)sum;
        }
        inode = file->inode;
        logical_offset = sqe->off;
        if (logical_offset > INT64_MAX)
                return 0;
        physical_fd = -1;
        request_size = total_len;
        physical_offset = logical_offset;

#ifdef POLYSTORE_POLYCACHE
        /* The direct io_uring path cannot keep the Poly cache coherent. */
        return 0;
#endif

        if (!total_len) {
                backup->sqe = sqe;
                backup->fd = sqe->fd;
                backup->off = sqe->off;
                backup->len = sqe->len;
                sqe->fd = POLYSTORE_FAST_FD(file->polyfd);
                return 1;
        }

        if (is_write)
                pthread_rwlock_wrlock(&inode->it_tree_lock);
        else
                pthread_rwlock_rdlock(&inode->it_tree_lock);

        if (inode->placement == BLK_PLACEMENT_FAST) {
                physical_fd = POLYSTORE_FAST_FD(file->polyfd);
        } else if (inode->placement == BLK_PLACEMENT_SLOW) {
                physical_fd = POLYSTORE_SLOW_FD(file->polyfd);
        } else if (inode->placement == BLK_PLACEMENT_BOTH ||
                   inode->placement == BLK_PLACEMENT_TBD) {
                entry = polystore_index_lookup(inode, logical_offset,
                                               logical_offset);
                if (!entry && is_write) {
                        int ret = uring_extent_create(file, logical_offset,
                                                      &entry);
                        if (ret < 0) {
                                pthread_rwlock_unlock(&inode->it_tree_lock);
                                return 0;
                        }
                }
                if (entry) {
                        if (entry->placement == BLK_PLACEMENT_FAST)
                                physical_fd = POLYSTORE_FAST_FD(file->polyfd);
                        else if (entry->placement == BLK_PLACEMENT_SLOW)
                                physical_fd = POLYSTORE_SLOW_FD(file->polyfd);

                        remaining = entry->it.last - logical_offset + 1;
                        if (request_size > remaining)
                                request_size = remaining;
                        physical_offset = entry->offset + logical_offset -
                                          entry->it.start;
                } else {
                        /* A missing Poly-index interval is a logical hole. */
                        request_size = 0;
                        physical_fd = POLYSTORE_FAST_FD(file->polyfd);
                }
        } else {
                pthread_rwlock_unlock(&inode->it_tree_lock);
                return 0;
        }

        if (!is_write) {
                if (logical_offset >= inode->size)
                        request_size = 0;
                else if (request_size > inode->size - logical_offset)
                        request_size = inode->size - logical_offset;
        }
        if (request_size > INT64_MAX - logical_offset)
                request_size = INT64_MAX - logical_offset;
        pthread_rwlock_unlock(&inode->it_tree_lock);

        if (physical_fd < 0 || request_size > UINT32_MAX)
                return 0;

        if (is_vector && request_size < total_len) {
                struct iovec *iov = (struct iovec *)(uintptr_t)sqe->addr;
                uint64_t left;

                backup->iov = calloc(sqe->len, sizeof(*backup->iov));
                if (!backup->iov)
                        return 0;
                memcpy(backup->iov, iov,
                       sqe->len * sizeof(*backup->iov));
                left = request_size;
                for (i = 0; i < sqe->len; ++i) {
                        size_t old_len = backup->iov[i].iov_len;
                        if (old_len > left) {
                                backup->iov[i].iov_len = (size_t)left;
                                left = 0;
                        } else {
                                left -= old_len;
                        }
                        if (left == 0 && i + 1 < sqe->len) {
                                ++i;
                                for (; i < sqe->len; ++i) {
                                        backup->iov[i].iov_len = 0;
                                }
                                break;
                        }
                }
                backup->addr = sqe->addr;
                sqe->addr = (uint64_t)(uintptr_t)backup->iov;
        }

        backup->sqe = sqe;
        backup->file = file;
        backup->inode = inode;
        backup->entry = entry;
        backup->fd = sqe->fd;
        backup->off = logical_offset;
        backup->is_write = is_write;
        backup->logical_end = logical_offset + request_size;
        backup->len = sqe->len;
        backup->bytes = (uint32_t)request_size;
        sqe->fd = physical_fd;
        sqe->off = physical_offset;
        if (sqe->opcode == IORING_OP_READ ||
            sqe->opcode == IORING_OP_WRITE ||
            sqe->opcode == IORING_OP_READ_FIXED ||
            sqe->opcode == IORING_OP_WRITE_FIXED)
                sqe->len = (uint32_t)request_size;
        return 1;
}

static void uring_ring_unmap(struct polystore_uring_ring *ring, void *addr) {
        if (ring->sq_ring == addr) {
                ring->sq_ring = NULL;
                ring->sq_head = NULL;
                ring->sq_tail = NULL;
                ring->sq_mask = NULL;
                ring->sq_array = NULL;
        }
        if ((void *)ring->sqes == addr)
                ring->sqes = NULL;
}

/* Returns 0 when handled, 1 when the original syscall should proceed. */
int polystore_io_uring_syscall(long syscall_number,
                               long arg0, long arg1, long arg2,
                               long arg3, long arg4, long arg5,
                               long *result) {
#if defined(SYS_io_uring_setup) && defined(SYS_io_uring_enter)
        if (syscall_number == SYS_io_uring_setup) {
                struct io_uring_params *params =
                        (struct io_uring_params *)(uintptr_t)arg1;
                long ret = syscall_no_intercept(SYS_io_uring_setup,
                                                (unsigned)arg0, params);
                if (ret >= 0 && params &&
                    !(params->flags & (IORING_SETUP_SQPOLL |
                                       IORING_SETUP_NO_MMAP)))
                        (void)uring_ring_store((int)ret, params);
                *result = ret;
                return 0;
        }

        if (syscall_number == SYS_io_uring_enter) {
                struct polystore_uring_ring *ring;
                struct polystore_uring_backup *backups = NULL;
                unsigned entries, head, tail, submit, i;
                long ret;
                int ring_fd = (int)arg0;
                int ring_index;

                pthread_once(&uring_locks_once, uring_locks_initialize);
                pthread_mutex_lock(&uring_rings_lock);
                ring = uring_ring_find(ring_fd);
                if (!ring || !ring->sq_head || !ring->sq_tail ||
                    !ring->sq_mask || !ring->sq_array || !ring->sqes) {
                        pthread_mutex_unlock(&uring_rings_lock);
                        return 1;
                }
                ring_index = (int)(ring - uring_rings);
                pthread_mutex_lock(&uring_submit_locks[ring_index]);
                pthread_mutex_unlock(&uring_rings_lock);

                entries = ring->params.sq_entries;
                submit = (unsigned)arg1;
                if (submit > entries)
                        submit = entries;
                backups = calloc(submit ? submit : 1, sizeof(*backups));
                if (!backups) {
                        pthread_mutex_unlock(&uring_submit_locks[ring_index]);
                        *result = -ENOMEM;
                        return 0;
                }
                head = __atomic_load_n(ring->sq_head, __ATOMIC_ACQUIRE);
                tail = __atomic_load_n(ring->sq_tail, __ATOMIC_ACQUIRE);
                if (submit > tail - head)
                        submit = tail - head;

                for (i = 0; i < submit; ++i) {
                        unsigned index = ring->sq_array[(head + i) &
                                                        *ring->sq_mask];
                        if (index >= entries)
                                continue;
                        (void)polystore_uring_translate(&ring->sqes[index],
                                                        &backups[i]);
                }

                ret = syscall_no_intercept(SYS_io_uring_enter,
                                           (unsigned)ring_fd,
                                           (unsigned)arg1,
                                           (unsigned)arg2,
                                           (unsigned)arg3,
                                           (void *)arg4,
                                           (size_t)arg5);
                if (ret > 0) {
                        unsigned done = (unsigned)ret < submit ?
                                        (unsigned)ret : submit;
                        for (i = 0; i < done; ++i) {
                                if (!backups[i].file)
                                        continue;
                                if (backups[i].is_write) {
                                        if (backups[i].inode) {
                                                pthread_rwlock_wrlock(
                                                  &backups[i].inode->it_tree_lock);
                                                if (backups[i].logical_end >
                                                    backups[i].inode->size)
                                                        backups[i].inode->size =
                                                          backups[i].logical_end;
                                                if (backups[i].entry) {
                                                        uint64_t extent_size =
                                                          backups[i].logical_end -
                                                          backups[i].entry->it.start;
                                                        if (extent_size >
                                                            backups[i].entry->size)
                                                                backups[i].entry->size =
                                                                  extent_size;
                                                }
                                                pthread_rwlock_unlock(
                                                  &backups[i].inode->it_tree_lock);
                                        }
                                }
                                if (!tls_task_ctx.task_ctx)
                                        continue;
                                tls_task_ctx.task_ctx->throughput +=
                                        backups[i].bytes;
                                if (!backups[i].is_write)
                                        tls_task_ctx.task_ctx->throughput_read +=
                                                backups[i].bytes;
                                else
                                        tls_task_ctx.task_ctx->throughput_write +=
                                                backups[i].bytes;
                        }
                }
                for (i = 0; i < submit; ++i) {
                        if (!backups[i].sqe)
                                continue;
                        if (backups[i].iov) {
                                backups[i].sqe->addr = backups[i].addr;
                                free(backups[i].iov);
                        }
                        backups[i].sqe->fd = backups[i].fd;
                        backups[i].sqe->off = backups[i].off;
                        backups[i].sqe->len = backups[i].len;
                }
                free(backups);
                pthread_mutex_unlock(&uring_submit_locks[ring_index]);
                *result = ret;
                return 0;
        }
#endif

        if (syscall_number == SYS_mmap) {
                struct polystore_uring_ring *ring;
                uint64_t offset = (uint64_t)arg5;
                long ret;

                pthread_mutex_lock(&uring_rings_lock);
                ring = uring_ring_find((int)arg4);
                if (!ring || (offset != IORING_OFF_SQ_RING &&
                              offset != IORING_OFF_CQ_RING &&
                              offset != IORING_OFF_SQES)) {
                        pthread_mutex_unlock(&uring_rings_lock);
                        return 1;
                }
                ret = syscall_no_intercept(SYS_mmap, (void *)arg0,
                                           (size_t)arg1, (int)arg2,
                                           (int)arg3, (int)arg4, (off_t)arg5);
                if (ret >= 0) {
                        void *addr = (void *)(uintptr_t)ret;
                        if (offset == IORING_OFF_SQES) {
                                ring->sqes = addr;
                        } else if (offset == IORING_OFF_SQ_RING) {
                                ring->sq_ring = addr;
                                ring->sq_head = (unsigned *)(addr +
                                        ring->params.sq_off.head);
                                ring->sq_tail = (unsigned *)(addr +
                                        ring->params.sq_off.tail);
                                ring->sq_mask = (unsigned *)(addr +
                                        ring->params.sq_off.ring_mask);
                                ring->sq_array = (unsigned *)(addr +
                                        ring->params.sq_off.array);
                        }
                }
                pthread_mutex_unlock(&uring_rings_lock);
                *result = ret;
                return 0;
        }

        if (syscall_number == SYS_munmap) {
                long ret = syscall_no_intercept(SYS_munmap,
                                                (void *)arg0, (size_t)arg1);
                if (ret == 0) {
                        int i;
                        pthread_mutex_lock(&uring_rings_lock);
                        for (i = 0; i < POLYSTORE_URING_MAX_RINGS; ++i)
                                if (uring_rings[i].active)
                                        uring_ring_unmap(&uring_rings[i],
                                                         (void *)arg0);
                        pthread_mutex_unlock(&uring_rings_lock);
                }
                *result = ret;
                return 0;
        }

        if (syscall_number == SYS_close) {
                struct polystore_uring_ring *ring;
                pthread_once(&uring_locks_once, uring_locks_initialize);
                pthread_mutex_lock(&uring_rings_lock);
                ring = uring_ring_find((int)arg0);
                if (ring) {
                        int ring_index = (int)(ring - uring_rings);
                        pthread_mutex_lock(&uring_submit_locks[ring_index]);
                        memset(ring, 0, sizeof(*ring));
                        pthread_mutex_unlock(&uring_submit_locks[ring_index]);
                }
                pthread_mutex_unlock(&uring_rings_lock);
        }

        return 1;
}
