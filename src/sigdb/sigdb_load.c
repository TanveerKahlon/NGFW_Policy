#include "ngfw/sigdb.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/* Bounds-check a (offset,length) span against the mapping. A signature database
 * is remotely-fetched data parsed by a privileged process; every offset in the
 * header is attacker-controlled until proven otherwise. */
static int span_ok(size_t size, uint32_t off, size_t count, size_t elem)
{
    if (off > size) return 0;
    size_t need = count * elem;
    if (elem && count > (size - off) / elem) return 0;   /* overflow-safe */
    return off + need <= size;
}

int ngfw_sigdb_open(ngfw_sigdb_t *db, const char *path)
{
    memset(db, 0, sizeof(*db));

    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("sigdb: open"); return -1; }

    struct stat st;
    if (fstat(fd, &st) != 0 || (size_t)st.st_size < sizeof(ngfw_sigdb_header_t)) {
        fprintf(stderr, "sigdb: %s is too small to be a database\n", path);
        close(fd);
        return -1;
    }

    void *m = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);                                   /* the mapping keeps the file alive */
    if (m == MAP_FAILED) { perror("sigdb: mmap"); return -1; }

    db->base = m;
    db->size = (size_t)st.st_size;
    db->hdr  = (const ngfw_sigdb_header_t *)m;

    if (db->hdr->magic != NGFW_SIGDB_MAGIC) {
        fprintf(stderr, "sigdb: bad magic 0x%08x (expected 0x%08x)\n",
                db->hdr->magic, NGFW_SIGDB_MAGIC);
        goto fail;
    }
    if (db->hdr->format_version != NGFW_SIGDB_VERSION) {
        fprintf(stderr, "sigdb: format version %u, engine supports %u\n",
                db->hdr->format_version, NGFW_SIGDB_VERSION);
        goto fail;
    }
    if (!span_ok(db->size, db->hdr->app_offset, db->hdr->app_count,
                 sizeof(ngfw_sigdb_app_t)) ||
        !span_ok(db->size, db->hdr->cidr_offset, db->hdr->cidr_count,
                 sizeof(ngfw_sigdb_cidr_t)) ||
        !span_ok(db->size, db->hdr->payload_offset, db->hdr->payload_count,
                 sizeof(ngfw_sigdb_payload_t)) ||
        !span_ok(db->size, db->hdr->domain_offset, db->hdr->domain_count,
                 sizeof(ngfw_sigdb_domain_t)) ||
        !span_ok(db->size, db->hdr->string_pool_offset,
                 db->hdr->string_pool_size, 1)) {
        fprintf(stderr, "sigdb: section offsets fall outside the file\n");
        goto fail;
    }
    /* The pool must be NUL-terminated or any name lookup can run off the end. */
    if (db->hdr->string_pool_size == 0 ||
        ((const char *)db->base)[db->hdr->string_pool_offset +
                                 db->hdr->string_pool_size - 1] != '\0') {
        fprintf(stderr, "sigdb: string pool is not NUL-terminated\n");
        goto fail;
    }

    db->apps    = (const ngfw_sigdb_app_t *)(db->base + db->hdr->app_offset);
    db->domains = (const ngfw_sigdb_domain_t *)(db->base + db->hdr->domain_offset);
    db->cidrs   = (const ngfw_sigdb_cidr_t *)(db->base + db->hdr->cidr_offset);
    db->payloads = (const ngfw_sigdb_payload_t *)(db->base + db->hdr->payload_offset);
    db->strings = (const char *)(db->base + db->hdr->string_pool_offset);
    return 0;

fail:
    munmap(m, (size_t)st.st_size);
    memset(db, 0, sizeof(*db));
    return -1;
}

void ngfw_sigdb_close(ngfw_sigdb_t *db)
{
    if (db && db->base) {
        munmap((void *)db->base, db->size);
        memset(db, 0, sizeof(*db));
    }
}

const char *ngfw_sigdb_app_name(const ngfw_sigdb_t *db, uint32_t app_id)
{
    for (uint32_t i = 0; i < db->hdr->app_count; i++) {
        if (db->apps[i].app_id == app_id) {
            uint32_t off = db->apps[i].name_off;
            if (off < db->hdr->string_pool_size) return db->strings + off;
            return "<corrupt>";
        }
    }
    return "<unknown>";
}
