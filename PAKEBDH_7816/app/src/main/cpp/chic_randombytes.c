#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

/* Android API 24 and the host both provide the kernel's CSPRNG here. */
int chic_randombytes(uint8_t *out, size_t len)
{
    int fd;
    size_t offset = 0;
    do { fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC); } while (fd < 0 && errno == EINTR);
    if (fd < 0) return -1;
    while (offset < len) {
        ssize_t count = read(fd, out + offset, len - offset);
        if (count > 0) offset += (size_t)count;
        else if (count < 0 && errno == EINTR) continue;
        else { close(fd); return -1; }
    }
    close(fd);
    return 0;
}
