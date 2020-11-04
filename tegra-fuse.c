/*
 * tegra-fuse.c
 *
 * Routines for reading/writing efuses via the
 * sysfs entries exposed by the the tegra-fuse driver.
 *
 * Copyright (c) 2019 Matthew Madison.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "tegra-fuse.h"

struct tegra_fuse_data_s {
	const char *name;
	int size_bits;
};

#define TEGRA_FUSE(x_, y_, z_) [TEGRA186_FUSE_##x_] = { y_, z_ },
static const struct tegra_fuse_data_s tegra186_fuse_data[TEGRA186_FUSE_COUNT] = { TEGRA186_FUSES };
#undef TEGRA_FUSE

#define TEGRA_FUSE(x_, y_, z_) [TEGRA194_FUSE_##x_] = { y_, z_ },
static const struct tegra_fuse_data_s tegra194_fuse_data[TEGRA194_FUSE_COUNT] = { TEGRA194_FUSES };
#undef TEGRA_FUSE

#define TEGRA_FUSE(x_, y_, z_) [TEGRA210_FUSE_##x_] = { y_, z_ },
static const struct tegra_fuse_data_s tegra210_fuse_data[TEGRA210_FUSE_COUNT] = { TEGRA210_FUSES };
#undef TEGRA_FUSE

static const struct {
	const char *chipname;
	const struct tegra_fuse_data_s *fuses;
	int fusecount;
} fuseinfo[TEGRA_SOCTYPE_COUNT] = {
	[TEGRA_SOCTYPE_186] = { "Tegra186", tegra186_fuse_data, TEGRA186_FUSE_COUNT },
	[TEGRA_SOCTYPE_194] = { "Tegra194", tegra194_fuse_data, TEGRA194_FUSE_COUNT },
	[TEGRA_SOCTYPE_210] = { "Tegra210", tegra210_fuse_data, TEGRA210_FUSE_COUNT },
};

static const char fuse_path[] = "/sys/devices/platform/tegra-fuse";

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
tegra_fuse_name (tegra_fusectx_t ctx, int fuseid)
{
	if (ctx == NULL) {
		errno = EINVAL;
		return NULL;
	}
	if (fuseid >= fuseinfo[ctx->soc].fusecount) {
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
tegra_fuse_id (tegra_fusectx_t ctx, const char *name)
{
	int i;

	if (ctx == NULL) {
		errno = EINVAL;
		return -1;
	}
	for (i = 0; i < fuseinfo[ctx->soc].fusecount; i++) {
		if (strcmp(name, fuseinfo[ctx->soc].fuses[i].name) == 0)
			return i;
	}

	errno = EINVAL;
	return -1;

} /* tegra_fuse_id */

/*
 * tegra_fuse_size
 *
 * Returns the size, in bits, of the fuse.
 */
int
tegra_fuse_size (tegra_fusectx_t ctx, int fuseid)
{
	if (ctx == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (fuseid >= fuseinfo[ctx->soc].fusecount) {
		errno = EINVAL;
		return -1;
	}
	return fuseinfo[ctx->soc].fuses[fuseid].size_bits;

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
	const char *path = (basepath == NULL ? fuse_path : basepath);
	ssize_t typelen;
	tegra_soctype_t soc;
	int fd;
	unsigned long chipid;
	char soctype[65];

	fd = open("/sys/module/tegra_fuse/parameters/tegra_chip_id", O_RDONLY);
	if (fd < 0)
		return NULL;
	typelen = read(fd, soctype, sizeof(soctype)-1);
	close(fd);
	if (typelen < 0)
		return NULL;
	while (typelen > 0 && soctype[typelen-1] == '\n') typelen--;
	soctype[typelen] = '\0';
	chipid = strtoul(soctype, NULL, 10);
	switch (chipid) {
	case 0x18:
		soc = TEGRA_SOCTYPE_186;
		break;
	case 0x19:
		soc = TEGRA_SOCTYPE_194;
		break;
	case 0x21:
		soc = TEGRA_SOCTYPE_210;
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
	ctx->sysfd = open(path, O_PATH|O_DIRECTORY);
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
tegra_fuse_read (tegra_fusectx_t ctx, int fuseid,
                 void *outbuf, size_t bufsiz)
{
	int fd;
	ssize_t n;
	char buf[256];

	if (ctx == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (fuseid >= fuseinfo[ctx->soc].fusecount) {
		errno = EINVAL;
		return -1;
	}
	fd = openat(ctx->sysfd, fuseinfo[ctx->soc].fuses[fuseid].name, O_RDONLY, 0);
	if (fd < 0)
		return -1;
	n = read(fd, buf, sizeof(buf)-1);
	close(fd);
	if (n < 0)
		return n;
	while (n > 0 && buf[n-1] == '\n')
		n -= 1;
	if (n < 2 || buf[0] != '0' || buf[1] != 'x') {
		errno = EIO;
		return -1;
	}
	if (n > (ssize_t) (bufsiz-3))
		n = bufsiz - 3;
	n -= 2; // for the leading '0x'
	if (n > 0)
		memcpy(outbuf, buf + 2, (size_t) n);
	*((char *)outbuf + n) = '\0';
	return n;

} /* tegra_fuse_read */

/*
 * tegra_fuse_write
 *
 * Blow fuses.
 */
ssize_t
tegra_fuse_write (tegra_fusectx_t ctx, int fuseid,
                  const void *buf, size_t buflen)
{
	int fd;
	ssize_t n;
	char writebuf[256];

	if (ctx == NULL) {
		errno = EINVAL;
		return -1;
	}
	/* reserve 2 bytes of writebuf for the '0x' prefix and 1 for terminating newline  */
	if (fuseid >= fuseinfo[ctx->soc].fusecount || buflen >= sizeof(writebuf)-3) {
		errno = EINVAL;
		return -1;
	}
	fd = openat(ctx->sysfd, fuseinfo[ctx->soc].fuses[fuseid].name, O_WRONLY, 0);
	if (fd < 0)
		return fd;
	writebuf[0] = '0';
	writebuf[1] = 'x';
	memcpy(writebuf + 2, buf, buflen);
	writebuf[buflen + 2] = '\n';
	n = write(fd, writebuf, buflen+3);
	close(fd);
	return (n == (buflen + 3) ? 0 : -1);

} /* tegra_fuse_write */
