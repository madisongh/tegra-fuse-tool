/*
 * tegra-fuse-tool.c
 *
 * Tool for getting/setting secure boot
 * fuse status for Tegra platforms.
 *
 * Copyright (c) 2019 Matthew Madison
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <sys/random.h>
#include "tegra-fuse.h"


typedef int (*option_routine_t)(tegra_fusectx_t ctx);

static struct option options[] = {
	{ "chip-id",		no_argument,	0, 'i' },
	{ "closed",		no_argument,	0, 'c' },
	{ "show",		no_argument,	0, 's' },
	{ "set-closed",		no_argument,	0, 'S' },
	{ "help",		no_argument,	0, 'h' },
	{ 0,			0,		0, 0   }
};
static const char *shortopts = ":icspSh";

static char *optarghelp[] = {
	"--chip-id            ",
	"--closed             ",
	"--show               ",
	"--set-closed         ",
	"--help               ",
};

static char *opthelp[] = {
	"show chip ID of the CPU",
	"show state of ODM_PRODUCTION_MODE fuse",
	"show secure boot fuse information",
	"program the JTAG_DISABLE and ODM_PRODUCTION_MODE fuses",
	"display this help text"
};


static int
allzeros (const void *buf)
{
	const char *cp;
	for (cp = buf; *cp == '0'; cp++);
	return (*cp == '\0');
}

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
 * show_chip_id
 *
 * Report the "chip ID" (SoC name).
 *
 */
static int
show_chip_id (tegra_fusectx_t ctx)
{
	char buf[32];

	if (tegra_fuse_soctype_name(ctx, buf, sizeof(buf)) < 0) {
		fprintf(stderr, "Could not retrieve SoC type name\n");
		return 1;
	}
	printf("%s\n", buf);
	return 0;

} /* show_chip_id */

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
	char buf[16];
	ssize_t n;
	int fuseid = tegra_fuse_id(ctx, "odm_production_mode");

	if (fuseid < 0) {
		fprintf(stderr, "Could not identify odm_production_mode fuse\n");
		return 1;
	}
	n = tegra_fuse_read(ctx, fuseid, buf, sizeof(buf));
	if (n <= 0) {
		fprintf(stderr, "Error reading odm_production_mode fuse\n");
		return 1;
	}
	printf("%s\n", (allzeros(buf) ? "OPEN" : "CLOSED"));
	return 0;

} /* show_sec_config_status */

static const char *
sbauth (unsigned long bsmode, tegra_soctype_t soc)
{
	if (soc == TEGRA_SOCTYPE_210)
		return (bsmode & 1) ? "PKC disabled" : "PKC enabled";

	if (soc == TEGRA_SOCTYPE_186)
		switch (bsmode & 3) {
			case 0:
			case 1:
				return "AES-CMAC using SBK";
			case 2:
				return "2048-bit RSA";
			case 3:
				return "NIST P-256 curve ECC";
		}

	if (soc == TEGRA_SOCTYPE_194)
		switch (bsmode & 3) {
			case 0:
				return "SHA2 hash";
			case 1:
				return "2048-bit RSA";
			case 2:
				return "3072-bit RSA";
			case 3:
				if (bsmode & (1<<7))
					return "Ed25519";
				else
					return "ECDSA with NIST P-256 curve";
		}


	return "UNKNOWN";

} /* sbauth */

static ssize_t
read_fuse (tegra_fusectx_t ctx, const char *name, char *buf, size_t bufsiz)
{
	int fuseid = tegra_fuse_id(ctx, name);

	if (fuseid < 0)
		return fuseid;
	return tegra_fuse_read(ctx, fuseid, buf, bufsiz);

} /* read_fuse */

/*
 * show_full
 *
 * Full secure boot fuse info.
 *
 */
static int
show_full (tegra_fusectx_t ctx)
{
	char chipname[32];
	char pm[16], pd[16], jtag[16], pubkey[256];
	unsigned long bsmode;
	tegra_soctype_t soc;
	ssize_t n;

	if (tegra_fuse_soctype(ctx, &soc) < 0) {
		fprintf(stderr, "ERR: could not identify SoC type\n");
		return 1;
	}
	n = read_fuse(ctx, "odm_production_mode", pm, sizeof(pm));
	if (n >= 0) {
		printf("Secure boot configuration: %s\n", (allzeros(pm) ? "OPEN" : "CLOSED"));
		if (soc == TEGRA_SOCTYPE_186 || soc == TEGRA_SOCTYPE_194)
			n = read_fuse(ctx, "boot_security_info", pd, sizeof(pd));
		else
			n = read_fuse(ctx, "pkc_disable", pd, sizeof(pd));
		if (n >= 0)
			bsmode = strtoul(pd, NULL, 16);

	}
	if (n >= 0)
		n = read_fuse(ctx, "arm_jtag_disable", jtag, sizeof(jtag));
	if (n >= 0)
		n = read_fuse(ctx, "public_key", pubkey, sizeof(pubkey));
	if (n < 0) {
		fprintf(stderr, "Error reading fuses\n");
		return 1;
	}

	printf("Secure boot auth:          %s\n", sbauth(bsmode, soc));
	if (soc != TEGRA_SOCTYPE_210)
		printf("Bootloader SBK encryption: %s\n", (bsmode & 4) ? "ENABLED" : "DISABLED");
	printf("JTAG interface:            %s\n", (allzeros(jtag) ? "ENABLED"  : "DISABLED"));
	printf("Secure boot public key:    %s\n", (allzeros(pubkey) ? "not set" : pubkey));

	/*
	 * The DK/SBK (210) or KEK[0-2] (186) are only readable if we are not
	 * in 'production mode'. KEKs are not exported by the driver on 194.
	 */
	if (allzeros(pm)) {
		char key[256];
		if (soc == TEGRA_SOCTYPE_210) {
			if (read_fuse(ctx, "device_key", key, sizeof(key)) >= 0)
				printf("Device key:                %s\n", key);
			if (read_fuse(ctx, "secure_boot_key", key, sizeof(key)) >= 0)
				printf("Secure boot key:           %s\n", key);
		} else if (soc == TEGRA_SOCTYPE_186) {
			if (read_fuse(ctx, "kek0", key, sizeof(key)) >= 0)
				printf("KEK0:                      %s\n", key);
			if (read_fuse(ctx, "kek1", key, sizeof(key)) >= 0)
				printf("KEK1:                      %s\n", key);
			if (read_fuse(ctx, "kek2", key, sizeof(key)) >= 0)
				printf("KEK2:                      %s\n", key);
		}
	}

	return 0;

} /* show_full */


/*
 * close_sec_config
 *
 * Programs the JTAGDIS fuse to disable the JTAG interface
 * and then programs the ODM_PRODUCTION_MODE fuse, after
 * checking that the PKC hash has been correctly programmed.
 * On 186/194 platforms, also ensure that BOOTSECINFO is set to
 * has bit 1 set (for RSA signature verification).  For tegra210
 * platforms, ensure that PKCDIS is *not* programmed.
 */
static int
close_sec_config (tegra_fusectx_t ctx)
{
	char pm[16], pubkey[256], jtd[16], pd[16];
	tegra_soctype_t soc;
	int fuseid;

	if (tegra_fuse_soctype(ctx, &soc) < 0) {
		fprintf(stderr, "ERR: could not identify SoC type\n");
		return 1;
	}
	if (read_fuse(ctx, "odm_production_mode", pm, sizeof(pm)) < 0) {
		fprintf(stderr, "Could not read odm_production_mode fuse for verification\n");
		return 1;
	}
	if (!allzeros(pm)) {
		printf("Boot security configuration already set to CLOSED\n");
		return 0;
	}
	if (read_fuse(ctx, "public_key", pubkey, sizeof(pubkey)) < 0) {
		fprintf(stderr, "Could not read public_key fuse to verify setting\n");
		return 1;
	}
	if (allzeros(pubkey)) {
		fprintf(stderr, "Public key hash has not been programmed - cancelling request\n");
		return 1;
	}
	if (soc == TEGRA_SOCTYPE_210) {
		if (read_fuse(ctx, "pkc_disable", pd, sizeof(pd)) < 0) {
			fprintf(stderr, "Could not read pkc_disable fuse for verification\n");
			return 1;
		}
		if (!allzeros(pd)) {
			fprintf(stderr, "pkc_disable fuse has been set - cancelling request\n");
			return 1;
		}
	} else {
		unsigned long bsmode;
		if (read_fuse(ctx, "boot_security_info", pd, sizeof(pd)) < 0) {
			fprintf(stderr, "Could not read boot_security_info fuse for verification\n");
			return 1;
		}
		bsmode = strtoul(pd, NULL, 16);
		if ((soc == TEGRA_SOCTYPE_186 && (bsmode & 3) != 2) ||
		    (soc == TEGRA_SOCTYPE_194 && (bsmode & 3) != 1)) {
			fprintf(stderr, "boot_security_info fuse not set for 2048-bit RSA - cancelling request\n");
			return 1;
		}
	}

	fuseid = tegra_fuse_id(ctx, "arm_jtag_disable");
	if (fuseid < 0 || tegra_fuse_read(ctx, fuseid, jtd, sizeof(jtd)) < 0) {
		fprintf(stderr, "Could not read arm_jtag_disable fuse for verification\n");
		return 1;
	}
	if (allzeros(jtd)) {
		if (tegra_fuse_write(ctx, fuseid, "1", 1) < 0) {
			fprintf(stderr, "Could not set arm_jtag_disable fuse\n");
			return 1;
		}
	}
	fuseid = tegra_fuse_id(ctx, "odm_production_mode");
	if (fuseid < 0 || tegra_fuse_write(ctx, fuseid, "1", 1) < 0) {
		fprintf(stderr, "Could not set odm_production_mode fuse\n");
		return 1;
	}
	printf("Boot security now set to CLOSED, power off device now.\n");
	return 0;

} /* close_sec_config */

/*
 * main program
 */
int
main (int argc, char * const argv[])
{
	int c, which, ret;
	tegra_fusectx_t ctx;
	option_routine_t dispatch = NULL;

	/*
	 * For now, at least, we allow only one option to
	 * be specified, so argc must be exactly 2.
	 */
	if (argc != 2) {
		print_usage();
		return 1;
	}

	c = getopt_long_only(argc, argv, shortopts, options, &which);
	if (c == -1) {
		perror("getopt");
		print_usage();
		return 1;
	}

	switch (c) {

		case 'h':
			print_usage();
			return 0;
		case 'i':
			dispatch = show_chip_id;
			break;
		case 'c':
			dispatch = show_sec_config_status;
			break;
		case 's':
			dispatch = show_full;
			break;
		case 'S':
		        dispatch = close_sec_config;
			break;
		default:
			fprintf(stderr, "Error: unrecognized option\n");
			print_usage();
			return 1;
	}

	if (dispatch == NULL) {
		fprintf(stderr, "Error in option processing\n");
		return 1;
	}

	ctx = tegra_fuse_context_open(NULL);
	if (ctx == 0) {
		fprintf(stderr, "Error accessing fuse configuration\n");
		return 1;
	}
	ret = dispatch(ctx);
	tegra_fuse_context_close(ctx);

	return ret;

} /* main */
