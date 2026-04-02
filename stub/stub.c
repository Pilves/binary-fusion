#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <stdint.h>

#ifdef USE_ZLIB
#include <zlib.h>
#endif

/*
 * This is the loader stub that gets compiled into the front of the fused binary.
 * The fused binary looks like: [this stub] [host exe] [guest exe] [trailer] [trailer_size]
 * At runtime we read our own file, find the trailer at the end, extract both
 * embedded executables to /tmp, run them one after the other, then clean up.
 */

#define TRAILER_SIZE 40
#define FLAG_COMPRESSED 1

struct trailer {
    uint64_t host_offset;
    uint64_t host_size;
    uint64_t guest_offset;
    uint64_t guest_size;
    uint32_t flags;
    char magic[4]; // should be "FUSE"
};

int read_trailer(int fd, struct trailer *t) {
    uint64_t tsize;

    // trailer_size is the last 8 bytes of the file
    lseek(fd, -(off_t)sizeof(uint64_t), SEEK_END);
    if (read(fd, &tsize, 8) != 8 || tsize != TRAILER_SIZE)
        return -1;

    // now read the trailer itself, right before the trailer_size
    lseek(fd, -(off_t)(tsize + 8), SEEK_END);
    if (read(fd, t, TRAILER_SIZE) != TRAILER_SIZE)
        return -1;

    if (memcmp(t->magic, "FUSE", 4) != 0)
        return -1;

    return 0;
}

// pulls out one of the embedded binaries into a temp file
int extract(int fd, uint64_t offset, uint64_t size, int decompress, char *outpath) {
    strcpy(outpath, "/tmp/.fuse_XXXXXX");
    int tmpfd = mkstemp(outpath);
    if (tmpfd == -1) { perror("mkstemp"); return -1; }

    lseek(fd, offset, SEEK_SET);

    unsigned char *buf = malloc(size);
    if (!buf) { perror("malloc"); close(tmpfd); return -1; }

    size_t got = 0;
    while (got < size) {
        ssize_t n = read(fd, buf + got, size - got);
        if (n <= 0) { free(buf); close(tmpfd); return -1; }
        got += n;
    }

#ifdef USE_ZLIB
    if (decompress) {
        // start with 10x the compressed size, grow if needed
        uLongf out_size = size * 10;
        unsigned char *out = malloc(out_size);
        if (!out) { free(buf); close(tmpfd); return -1; }

        int ret;
        while ((ret = uncompress(out, &out_size, buf, size)) == Z_BUF_ERROR) {
            out_size *= 2;
            out = realloc(out, out_size);
            if (!out) { free(buf); close(tmpfd); return -1; }
        }
        if (ret != Z_OK) {
            fprintf(stderr, "decompression failed\n");
            free(out); free(buf); close(tmpfd);
            return -1;
        }
        write(tmpfd, out, out_size);
        free(out);
    } else
#endif
    {
        (void)decompress;
        write(tmpfd, buf, size);
    }

    free(buf);
    fchmod(tmpfd, 0755);
    close(tmpfd);
    return 0;
}

int run(const char *path, char *envp[], int redir) {
    pid_t pid = fork();
    if (pid == -1) { perror("fork"); return -1; }

    if (pid == 0) {
        // for the guest binary, we redirect its stdout to our stderr
        // so you can do ./fused > host.txt 2> guest.txt
        if (redir)
            dup2(STDERR_FILENO, STDOUT_FILENO);
        char *argv[] = {(char *)path, NULL};
        execve(path, argv, envp);
        perror("execve");
        _exit(127);
    }

    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

int main(int argc, char *argv[], char *envp[]) {
    // /proc/self/exe is a symlink to our own binary, most reliable way to read ourselves
    int fd = open("/proc/self/exe", O_RDONLY);
    if (fd == -1) {
        fd = open(argv[0], O_RDONLY);
        if (fd == -1) { perror("open"); return 1; }
    }

    struct trailer t;
    if (read_trailer(fd, &t) != 0) {
        fprintf(stderr, "bad trailer, is this actually a fused binary?\n");
        close(fd);
        return 1;
    }

    char host_path[256], guest_path[256];

    // extract and run host first
    if (extract(fd, t.host_offset, t.host_size, 0, host_path) != 0)
        return 1;
    int ret1 = run(host_path, envp, 0);
    unlink(host_path);

    // then guest
    int compressed = t.flags & FLAG_COMPRESSED;
    if (extract(fd, t.guest_offset, t.guest_size, compressed, guest_path) != 0)
        return 1;
    int ret2 = run(guest_path, envp, 1);
    unlink(guest_path);

    close(fd);
    return ret1 != 0 ? ret1 : ret2;
}
