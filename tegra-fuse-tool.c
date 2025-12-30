/*
 * tegra-fuse-tool.c
 *
 * Tool for getting/setting secure boot
 * fuse status for Tegra platforms.
 *
 * Copyright (c) 2019-2026, Matthew Madison
 */

#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <stdint.h>
#include "tegra-fuse.h"


typedef int (*option_routine_t)(tegra_fusectx_t ctx);
static const char *fuse_name = NULL;

static struct option options[] = {
	{ "soc-type",		no_argument,		0, 't' },
	{ "closed",		no_argument,		0, 'c' },
	{ "show",		required_argument,		0, 's' },
	{ "help",		no_argument,		0, 'h' },
	{ 0,			0,			0, 0   }
};
static const char *shortopts = ":tcs:h";

static char *optarghelp[] = {
	"--soc-type	      ",
	"--closed	      ",
	"--show	FUSENAME  ",
	"--help		      ",
};

static char *opthelp[] = {
	"show SoC type of the CPU",
	"show secure boot state",
	"show specific fuse",
	"display this help text"
};


static void
print_usage (void)
{
	int i;
	printf("\nUsage:\n");
	printf("\ttegra-fuse-tool <option>\n\n");
	printf("Options (use only one per invocation):\n");
	for (i = 0; i < sizeof(options)/sizeof(options[0]) && options[i].name != 0; i++) {
		printf(" %s\t%c%c\t%s\n",
		       optarghelp[i],
		       (options[i].val == 0 ? ' ' : '-'),
		       (options[i].val == 0 ? ' ' : options[i].val),
		       opthelp[i]);
	}

} /* print_usage */

/*
 * show_soctype
 *
 * Report the SoC name.
 *
 */
static int
show_soctype (tegra_fusectx_t ctx)
{
	char buf[32];

	if (tegra_fuse_soctype_name(ctx, buf, sizeof(buf)) < 0) {
		fprintf(stderr, "Could not retrieve SoC type name\n");
		return 1;
	}
	printf("%s\n", buf);
	return 0;

} /* show_soctype */

/*
 * show_sec_config_status
 *
 * Brief open/closed status check,
 * mainly for script use.
 *
 */
static int
show_sec_config_status (tegra_fusectx_t ctx)
{
	uint32_t secmode;
	tegra_soctype_t soc;

	if (tegra_fuse_soctype(ctx, &soc) < 0) {
		fprintf(stderr, "ERR: could not identify SoC type\n");
		return 1;
	}
	if (soc == TEGRA_SOCTYPE_234) {
		fprintf(stderr, "ERR: not supported on T234\n");
		return 1;
	}
	if (tegra_fuse_read(ctx, TEGRA_FUSE_SECURITY_MODE, &secmode, sizeof(secmode)) < 0) {
		fprintf(stderr, "Error reading security mode fuse\n");
		return 1;
	}
	printf("%s\n", (secmode == 0 ? "OPEN" : "CLOSED"));
	return 0;

} /* show_sec_config_status */

static ssize_t
read_fuse (tegra_fusectx_t ctx, const char *name, void *buf, size_t bufsiz)
{
	tegra_fuse_t fuseid;

	if (tegra_fuse_id(ctx, name, &fuseid) < 0)
		return -1;

	return tegra_fuse_read(ctx, fuseid, buf, bufsiz);

} /* read_fuse */

static int
print_bytes (const void *bufp, size_t bufsiz)
{
	const uint8_t *bp = bufp;
	while (bufsiz-- > 0) {
		printf("%02x", *bp++);
	}
	return 0;

} /* print_bytes */

static int
print_one_fuse (tegra_fusectx_t ctx, tegra_fuse_t fuseid)
{
	uint8_t *buf;
	ssize_t s = tegra_fuse_size(ctx, fuseid);
	if (s < 0) {
		perror(fuse_name);
		return 1;
	}
	if (s == sizeof(uint32_t)) {
		uint32_t val;
		if (tegra_fuse_read(ctx, fuseid, &val, sizeof(val)) < 0) {
			perror("tegra_fuse_read");
			return 1;
		}
		printf("%s: 0x%08x\n", fuse_name, val);
		return 0;
	}
	buf = calloc(s, sizeof(uint8_t));
	if (buf == NULL) {
		perror("calloc");
		return 1;
	}
	if (tegra_fuse_read(ctx, fuseid, buf, s) < 0) {
		perror("tegra_fuse_read");;
		free(buf);
		return 1;
	}
	printf("%s: 0x", fuse_name);
	print_bytes(buf, s);
	printf("\n");
	free(buf);
	return 0;

} /* print_one_fuse */

static int
print_pkhash(tegra_fusectx_t ctx)
{
	uint8_t val_l[32], val_r[32];
	if (tegra_fuse_read(ctx, TEGRA_FUSE_PUBLIC_KEY_HASH_L, val_l, sizeof(val_l)) < 0 ||
		tegra_fuse_read(ctx, TEGRA_FUSE_PUBLIC_KEY_HASH_R, val_r, sizeof(val_r)) < 0) {
		perror("pkhash");
		return 1;
	}
	printf("public_key_hash: 0x");
	print_bytes(val_l, sizeof(val_l));
	print_bytes(val_r, sizeof(val_r));
	printf("\n");
	return 0;

} /* print_pkhash */

static int
print_chipid(tegra_fusectx_t ctx, bool do_br_cid)
{
	uint32_t vendor, fab, lot0, lot1, wafer, x, y;
	ssize_t rc;

	rc = tegra_fuse_read(ctx, TEGRA_FUSE_BRCID_VENDOR, &vendor, sizeof(vendor));
	if (rc > 0)
		rc = tegra_fuse_read(ctx, TEGRA_FUSE_BRCID_FAB, &fab, sizeof(fab));
	if (rc > 0)
		rc = tegra_fuse_read(ctx, TEGRA_FUSE_BRCID_WAFER, &wafer, sizeof(wafer));
	if (rc > 0)
		rc = tegra_fuse_read(ctx, TEGRA_FUSE_BRCID_LOT0, &lot0, sizeof(lot0));
	if (do_br_cid && rc > 0)
		rc = tegra_fuse_read(ctx, TEGRA_FUSE_BRCID_LOT1, &lot1, sizeof(lot1));
	if (rc > 0)
		rc = tegra_fuse_read(ctx, TEGRA_FUSE_BRCID_X, &x, sizeof(x));
	if (rc > 0)
		rc = tegra_fuse_read(ctx, TEGRA_FUSE_BRCID_Y, &y, sizeof(y));
	if (rc < 0) {
		perror("chipid");
		return 1;
	}
	vendor &= 0xf;
	fab &= 0x3f;
	wafer &= 0x3f;
	x &= 0x1ff;
	y &= 0x1ff;

	if (do_br_cid) {
		printf("br_cid: 0x%01x%08x%08x%08x\n", vendor,
			((lot0 >> 6) & 0x3ffffff) | (fab << 26),
			((lot1 >> 2) & 0x3ffffff) | ((lot0 & 0x3f) << 26),
			(y << 6) | (x << 15) | (wafer << 24) | ((lot1 & 0x3) << 30));
	} else {
		uint32_t cid = 8; /* Same for t234 and t264 */
		uint64_t ecid;
		uint32_t lot = 0;
		int i;
		unsigned int digit;
		lot0 <<= 2;
		for (i = 0; i < 5; i++, lot0 <<= 6) {
			digit = (lot0 & 0xFC000000) >> 26;
			if (digit >= 36) {
				fprintf(stderr, "error: invalid lot code digit when generating ECID\n");
				return 1;
			}
			lot = lot * 36 + digit;
		}
		ecid = (uint64_t) y | ((uint64_t) x << 9) | ((uint64_t) wafer << 18) | ((uint64_t) lot << 24) |
			((uint64_t) fab << 50) | ((uint64_t) vendor << 56) | (8ULL << 60);
		printf("ecid: 0x%lx\n", ecid);
	}

}
static int
show_one_fuse (tegra_fusectx_t ctx)
{
	tegra_fuse_t fuseid;

	if (fuse_name == NULL) {
		fprintf(stderr, "error: missing fuse name\n");
		return 1;
	}
	if (strcmp(fuse_name, "public_key_hash") == 0) {
		return print_pkhash(ctx);
	}
	if (strcmp(fuse_name, "ecid") == 0) {
		return print_chipid(ctx, false);
	}
	if (strcmp(fuse_name, "br_cid") == 0) {
		return print_chipid(ctx, true);
	}
	if (tegra_fuse_id(ctx, fuse_name, &fuseid) < 0) {
		fprintf(stderr, "unrecognized fuse name: %s\n", fuse_name);
		return 1;
	}
	return print_one_fuse(ctx, fuseid);

} /* show_one_fuse */

/*
 * show_all_fuses
 *
 */
static int
show_all_fuses (tegra_fusectx_t ctx)
{
	void *iter_ctx;

	for (fuse_name = tegra_first_fuse_name(ctx, &iter_ctx);
		fuse_name != NULL;
		fuse_name = tegra_next_fuse_name(ctx, &iter_ctx)) {
		if (show_one_fuse(ctx))
			return 1;
		}
	return 0;

} /* show_all_fuses */


/*
 * main program
 */
int
main (int argc, char * const argv[])
{
	int c, which, ret;
	tegra_fusectx_t ctx;
	option_routine_t dispatch = NULL;

	c = getopt_long_only(argc, argv, shortopts, options, &which);

	switch (c) {

		case 'h':
			print_usage();
			return 0;
		case 't':
			dispatch = show_soctype;
			break;
		case 'c':
			dispatch = show_sec_config_status;
			break;
		case 's':
			dispatch = show_one_fuse;
			fuse_name = strdup(optarg);
			break;
		case '?':
			fprintf(stderr, "Error: unrecognized option\n");
			print_usage();
			return 1;
		default:
			break;
	}

	ctx = tegra_fuse_context_open(NULL);
	if (ctx == 0) {
		fprintf(stderr, "Error accessing fuse configuration\n");
		return 1;
	}
	ret = (dispatch == NULL ? show_all_fuses(ctx) : dispatch(ctx));
	tegra_fuse_context_close(ctx);

	return ret;

} /* main */
