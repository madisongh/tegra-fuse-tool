/*
 * tegra-fuse.c
 *
 * Routines for reading/writing efuses via the
 * sysfs entries exposed by the the tegra-fuse driver.
 *
 * Copyright (c) 2019-2026, Matthew Madison.
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>
#include "tegra-fuse.h"

struct tegra_fuse_data_s {
	const char *name;
	off_t offset;
	size_t size_bytes;
	bool visible;
};

#define TEGRA_FUSE(x_, y_, z_, a_, b_) [TEGRA_FUSE_##x_] = { y_, z_, a_ , b_ },
static const struct tegra_fuse_data_s tegra_fuse_data[TEGRA_FUSE_COUNT] = { TEGRAxxx_FUSES };
#undef TEGRA_FUSE

static const char fuse_path_t234[] = "/sys/bus/nvmem/devices/fuse/nvmem";
static const char fuse_path_t264[] = "/sys/bus/nvmem/devices/efuse0/nvmem";

static const struct {
	const char *chipname;
	const char *nvmem_path;
	const struct tegra_fuse_data_s *fuses;
	size_t fusecount;
} fuseinfo[TEGRA_SOCTYPE_COUNT] = {
	[TEGRA_SOCTYPE_234] = { "Tegra234", fuse_path_t234, tegra_fuse_data, TEGRA_FUSE_COUNT },
	[TEGRA_SOCTYPE_264] = { "Tegra264", fuse_path_t264, tegra_fuse_data, TEGRA_FUSE_COUNT },
};


struct tegra_fusectx_s {
	int sysfd;
	tegra_soctype_t soc;
};

/*
 * tegra_fuse_name
 *
 * Returns the character string for the fuse (as exposed in sysfs).
 */
const char *
tegra_fuse_name (tegra_fusectx_t ctx, tegra_fuse_t fuseid)
{
	if (ctx == NULL) {
		errno = EINVAL;
		return NULL;
	}
	if ((size_t) fuseid >= fuseinfo[ctx->soc].fusecount) {
		errno = EINVAL;
		return NULL;
	}

	return fuseinfo[ctx->soc].fuses[fuseid].name;
}

/*
 * tegra_fuse_id
 *
 * Returns the fuse ID value for a named fuse.
 */
int
tegra_fuse_id (tegra_fusectx_t ctx, const char *name, tegra_fuse_t *fuseid)
{
	int i;

	if (ctx == NULL) {
		errno = EINVAL;
		return -1;
	}
	for (i = 0; i < fuseinfo[ctx->soc].fusecount; i++) {
		if (fuseinfo[ctx->soc].fuses[i].visible &&
			strcmp(name, fuseinfo[ctx->soc].fuses[i].name) == 0) {
			*fuseid = (tegra_fuse_t) i;
			return 0;
		}
	}

	errno = EINVAL;
	return -1;

} /* tegra_fuse_id */

/*
 * tegra_fuse_size
 *
 * Returns the size, in bits, of the fuse.
 */
ssize_t
tegra_fuse_size (tegra_fusectx_t ctx, tegra_fuse_t fuseid)
{
	if (ctx == NULL) {
		errno = EINVAL;
		return (ssize_t) -1;
	}

	if ((size_t) fuseid >= fuseinfo[ctx->soc].fusecount) {
		errno = EINVAL;
		return (ssize_t) -1;
	}
	return (ssize_t) fuseinfo[ctx->soc].fuses[(unsigned int) fuseid].size_bytes;

} /* tegra_fuse_size */

/*
 * tegra_fuse_soctype
 *
 * Returns the SOC type.
 */
int
tegra_fuse_soctype (tegra_fusectx_t ctx, tegra_soctype_t *soc)
{
	if (ctx == NULL || soc == NULL) {
		errno = EINVAL;
		return -1;
	}
	*soc = ctx->soc;
	return 0;

} /* tegra_fuse_soctype */

/*
 * tegra_fuse_soctype_name
 *
 * Returns the name of the type of SoC/CPU chip
 */
ssize_t
tegra_fuse_soctype_name (tegra_fusectx_t ctx, char *buf, size_t bufsiz)
{
	const char *name;
	size_t namelen;

	if (ctx == NULL) {
		errno = EINVAL;
		return -1;
	}
	name = fuseinfo[ctx->soc].chipname;
	namelen = strlen(name);
	if (bufsiz <= namelen) {
		errno = EINVAL;
		return -1;
	}
	memcpy(buf, name, namelen);
	buf[namelen] = '\0';
	return namelen;

} /* tegra_fuse_soctype_name */

/*
 * tegra_fuse_context_open
 *
 * Set up a context for working with the fuses.
 */
tegra_fusectx_t
tegra_fuse_context_open (const char *basepath)
{
	tegra_fusectx_t ctx;
	ssize_t typelen;
	tegra_soctype_t soc;
	int fd;
	unsigned long chipid;
	char soctype[65];

	fd = open("/sys/devices/soc0/soc_id", O_RDONLY);

	typelen = read(fd, soctype, sizeof(soctype)-1);
	close(fd);
	if (typelen < 0)
		return NULL;
	while (typelen > 0 && soctype[typelen-1] == '\n') typelen--;
	soctype[typelen] = '\0';

	chipid = strtoul(soctype, NULL, 10);

	switch (chipid) {
	case 0x23:
		soc = TEGRA_SOCTYPE_234;
		break;
	case 0x26:
		soc = TEGRA_SOCTYPE_264;
		break;
	default:
		errno = ENXIO;
		return NULL;
	}
	ctx = malloc(sizeof(struct tegra_fusectx_s));
	if (ctx == NULL)
		return ctx;

	memset(ctx, 0, sizeof(struct tegra_fusectx_s));
	ctx->soc = soc;
	ctx->sysfd = open(basepath == NULL ? fuseinfo[soc].nvmem_path : basepath, O_RDONLY);
	if (ctx->sysfd < 0) {
		free(ctx);
		return NULL;
	}

	return ctx;

} /* tegra_fuse_context_open */

/*
 * tegra_fuse_context_close
 *
 * Clean up.
 */
void
tegra_fuse_context_close (tegra_fusectx_t ctx)
{
	if (ctx == NULL)
		return;
	close(ctx->sysfd);
	free(ctx);

} /* tegra_fuse_context_close */

/*
 * tegra_fuse_read
 *
 * Read a fuse setting.
 */
ssize_t
tegra_fuse_read (tegra_fusectx_t ctx, tegra_fuse_t fuseid,
                 void *outbuf, size_t bufsiz)
{
	ssize_t n;
	size_t remain;
	uint32_t buf[64];
	uint8_t *bufp = (uint8_t *) &buf[0];

	if (ctx == NULL) {
		errno = EINVAL;
		return -1;
	}
	if ((size_t) fuseid >= fuseinfo[ctx->soc].fusecount) {
		errno = EINVAL;
		return -1;
	}
	const struct tegra_fuse_data_s *fuse_data = &fuseinfo[ctx->soc].fuses[fuseid];
	if (bufsiz > fuse_data->size_bytes) {
		bufsiz = fuse_data->size_bytes;
	} else if (bufsiz < fuse_data->size_bytes) {
		errno = EINVAL;
		return -1;
	}
	if (lseek(ctx->sysfd, fuseinfo[ctx->soc].fuses[fuseid].offset, SEEK_SET) < 0)
		return -1;
	for (remain = bufsiz; remain > 0; remain -= n, bufp += n) {
		n = read(ctx->sysfd, bufp, remain);
		if (n < 0)
			return n;
	}
	if (bufsiz == 4) {
		*(uint32_t *) outbuf = buf[0];
	} else {
		memcpy(outbuf, buf, bufsiz);
	}
	return (ssize_t) bufsiz;

} /* tegra_fuse_read */

/*
 * tegra_fuse_write
 *
 * Blow fuses. Not currently supported by the NVMEM driver.
 */
ssize_t
tegra_fuse_write (tegra_fusectx_t ctx, tegra_fuse_t fuseid,
                  const void *buf, size_t buflen)
{
	errno = EOPNOTSUPP;
	return -1;

} /* tegra_fuse_write */

const char *
tegra_first_fuse_name (tegra_fusectx_t ctx, void **iter_ctx)
{
	unsigned int i;

	if (iter_ctx == NULL)
		return NULL;
	for (i = 0; i < fuseinfo[ctx->soc].fusecount && !fuseinfo[ctx->soc].fuses[i].visible; i++);
	if (i >= fuseinfo[ctx->soc].fusecount) {
		return NULL;
	}
	*(unsigned int *)iter_ctx = i;
	return fuseinfo[ctx->soc].fuses[i].name;

} /* tegra_first_fuse_name */

const char *
tegra_next_fuse_name (tegra_fusectx_t ctx, void **iter_ctx)
{
	unsigned int i;
	const char *retval;

	if (iter_ctx == NULL)
		return NULL;
	i = *(unsigned int *) iter_ctx;
	for (i += 1; i < fuseinfo[ctx->soc].fusecount && !fuseinfo[ctx->soc].fuses[i].visible; i++);
	if (i < fuseinfo[ctx->soc].fusecount)
		retval = fuseinfo[ctx->soc].fuses[i].name;
	else if (i == fuseinfo[ctx->soc].fusecount)
		retval = "public_key_hash";
	else if (i == fuseinfo[ctx->soc].fusecount + 1)
		retval = "ecid";
	else if (i == fuseinfo[ctx->soc].fusecount + 2)
		retval = "br_cid";
	else
		return NULL;
	*(unsigned int *)iter_ctx = i;
	return retval;

} /* tegra_next_fuse_name */
