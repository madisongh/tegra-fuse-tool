#ifndef tegra_fuse_h__
#define tegra_fuse_h__
/*
 * tegra-fuse.h
 *
 * Definitions for tegra efuses.
 *
 * Copyright (c) 2019 Matthew Madison.
 */

#include <stdlib.h>

#undef TEGRA_FUSE

#define TEGRA186_FUSES \
	TEGRA_FUSE(ODMRES0,	"reserved_odm0",	32)  \
	TEGRA_FUSE(ODMRES1,	"reserved_odm1",	32)  \
	TEGRA_FUSE(ODMRES2,	"reserved_odm2",	32)  \
	TEGRA_FUSE(ODMRES3,	"reserved_odm3",	32)  \
	TEGRA_FUSE(ODMRES4,	"reserved_odm4",	32)  \
	TEGRA_FUSE(ODMRES5,	"reserved_odm5",	32)  \
	TEGRA_FUSE(ODMRES6,	"reserved_odm6",	32)  \
	TEGRA_FUSE(ODMRES7,	"reserved_odm7",	32)  \
	TEGRA_FUSE(ODMLOCK, 	"odm_lock", 		4)   \
	TEGRA_FUSE(JTAGDIS,	"arm_jtag_disable",	1)   \
	TEGRA_FUSE(PRODMODE,	"odm_production_mode",	1)   \
	TEGRA_FUSE(BOOTSECINFO,	"boot_security_info",	6)   \
	TEGRA_FUSE(SECBOOTKEY,	"secure_boot_key",	128) \
	TEGRA_FUSE(PUBKEY,	"public_key",		256) \
	TEGRA_FUSE(KEK0,	"kek0",			128) \
	TEGRA_FUSE(KEK1,	"kek1",			128) \
	TEGRA_FUSE(KEK2,	"kek2",			128) \
	TEGRA_FUSE(ODMINFO,	"odm_info",		16)

#define TEGRA194_FUSES \
	TEGRA_FUSE(ODMRES0,	"reserved_odm0",	32)  \
	TEGRA_FUSE(ODMRES1,	"reserved_odm1",	32)  \
	TEGRA_FUSE(ODMRES2,	"reserved_odm2",	32)  \
	TEGRA_FUSE(ODMRES3,	"reserved_odm3",	32)  \
	TEGRA_FUSE(ODMRES4,	"reserved_odm4",	32)  \
	TEGRA_FUSE(ODMRES5,	"reserved_odm5",	32)  \
	TEGRA_FUSE(ODMRES6,	"reserved_odm6",	32)  \
	TEGRA_FUSE(ODMRES7,	"reserved_odm7",	32)  \
	TEGRA_FUSE(ODMRES8,	"reserved_odm8",	32)  \
	TEGRA_FUSE(ODMRES9,	"reserved_odm9",	32)  \
	TEGRA_FUSE(ODMRES10,	"reserved_odm10",	32)  \
	TEGRA_FUSE(ODMRES11,	"reserved_odm11",	32)  \
	TEGRA_FUSE(ODMLOCK, 	"odm_lock", 		4)   \
	TEGRA_FUSE(JTAGDIS,	"arm_jtag_disable",	1)   \
	TEGRA_FUSE(PRODMODE,	"odm_production_mode",	1)   \
	TEGRA_FUSE(SECBOOTKEY,	"secure_boot_key",	128) \
	TEGRA_FUSE(PUBKEY,	"public_key",		256) \
	TEGRA_FUSE(BOOTSECINFO,	"boot_security_info",	16)   \
	TEGRA_FUSE(ODMINFO,	"odm_info",		16)

#define TEGRA210_FUSES \
	TEGRA_FUSE(ODMRES0,	"reserved_odm0",	32)  \
	TEGRA_FUSE(ODMRES1,	"reserved_odm1",	32)  \
	TEGRA_FUSE(ODMRES2,	"reserved_odm2",	32)  \
	TEGRA_FUSE(ODMRES3,	"reserved_odm3",	32)  \
	TEGRA_FUSE(ODMRES4,	"reserved_odm4",	32)  \
	TEGRA_FUSE(ODMRES5,	"reserved_odm5",	32)  \
	TEGRA_FUSE(ODMRES6,	"reserved_odm6",	32)  \
	TEGRA_FUSE(ODMRES7,	"reserved_odm7",	32)  \
	TEGRA_FUSE(ODMLOCK, 	"odm_lock", 		4)   \
	TEGRA_FUSE(DEVKEY,	"device_key",		32)  \
	TEGRA_FUSE(JTAGDIS,	"arm_jtag_disable",	1)   \
	TEGRA_FUSE(PRODMODE,	"odm_production_mode",	1)   \
	TEGRA_FUSE(SECBOOT_DEVCFG,"sec_boot_dev_cfg",	16)  \
	TEGRA_FUSE(SECBOOTKEY,	"secure_boot_key",	128) \
	TEGRA_FUSE(PUBKEY,	"public_key",		256) \
	TEGRA_FUSE(PKCDIS,	"pkc_disable",		1)

#define TEGRA_FUSE(x_, y_, z_) TEGRA186_FUSE_##x_,
typedef enum {
	TEGRA186_FUSES
	TEGRA186_FUSE_COUNT__
} tegra186_fuse_t;
#undef TEGRA_FUSE
#define TEGRA186_FUSE_COUNT ((int) TEGRA186_FUSE_COUNT__)

#define TEGRA_FUSE(x_, y_, z_) TEGRA194_FUSE_##x_,
typedef enum {
	TEGRA194_FUSES
	TEGRA194_FUSE_COUNT__
} tegra194_fuse_t;
#undef TEGRA_FUSE
#define TEGRA194_FUSE_COUNT ((int) TEGRA194_FUSE_COUNT__)

#define TEGRA_FUSE(x_, y_, z_) TEGRA210_FUSE_##x_,
typedef enum {
	TEGRA210_FUSES
	TEGRA210_FUSE_COUNT__
} tegra210_fuse_t;
#undef TEGRA_FUSE
#define TEGRA210_FUSE_COUNT ((int) TEGRA210_FUSE_COUNT__)

typedef enum {
	TEGRA_SOCTYPE_186,
	TEGRA_SOCTYPE_194,
	TEGRA_SOCTYPE_210,
	TEGRA_SOCTYPE_COUNT__
} tegra_soctype_t;
#define TEGRA_SOCTYPE_COUNT ((int) TEGRA_SOCTYPE_COUNT__)

struct tegra_fusectx_s;
typedef struct tegra_fusectx_s *tegra_fusectx_t;

tegra_fusectx_t tegra_fuse_context_open(const char *basepath);
int tegra_fuse_soctype(tegra_fusectx_t ctx, tegra_soctype_t *soc);
ssize_t tegra_fuse_soctype_name(tegra_fusectx_t ctx, char *buf, size_t bufsiz);
void tegra_fuse_context_close(tegra_fusectx_t ctx);
ssize_t tegra_fuse_read(tegra_fusectx_t ctx, unsigned int fuseid, void *buf, size_t bufsiz);
ssize_t tegra_fuse_write(tegra_fusectx_t ctx, unsigned int fuseid, const void *buf, size_t bufsiz);
const char *tegra_fuse_name(tegra_fusectx_t ctx, unsigned int fuseid);
int tegra_fuse_id(tegra_fusectx_t ctx, const char *fusename);
unsigned int tegra_fuse_count(tegra_fusectx_t ctx);
int tegra_fuse_size(tegra_fusectx_t ctx, unsigned int fuseid);

#endif /* tegra_fuse_h__ */
