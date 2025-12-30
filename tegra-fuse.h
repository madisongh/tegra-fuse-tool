#ifndef tegra_fuse_h__
#define tegra_fuse_h__
/*
 * tegra-fuse.h
 *
 * Definitions for tegra efuses.
 *
 * Copyright (c) 2019-2026, Matthew Madison.
 */

#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>

#undef TEGRA_FUSE

/*
 * The following fuses are defined in the same locations
 * for both T234 (Orin) and T264 (Thor).
 */
#define TEGRAxxx_FUSES \
	TEGRA_FUSE(BOOT_SECURITY_INFO,       "boot_security_info",       0x168,  4, true) \
	TEGRA_FUSE(BRCID_VENDOR,             "brcid_vendor",             0x100,  4, false) \
	TEGRA_FUSE(BRCID_FAB,                "brcid_fab",                0x104,  4, false) \
	TEGRA_FUSE(BRCID_LOT0,               "brcid_lot0",               0x108,  4, false) \
	TEGRA_FUSE(BRCID_LOT1,               "brcid_lot1",               0x10c,  4, false) \
	TEGRA_FUSE(BRCID_WAFER,              "brcid_wafer",              0x110,  4, false) \
	TEGRA_FUSE(BRCID_X,                  "brcid_x",                  0x114,  4, false) \
	TEGRA_FUSE(BRCID_Y,                  "brcid_y",                  0x118,  4, false) \
	TEGRA_FUSE(ODMID,                    "odmid",                    0x308,  8, true) \
	TEGRA_FUSE(ODMINFO,                  "odminfo",                  0x19c,  4, true) \
	TEGRA_FUSE(ODM_LOCK,                 "odm_lock",                 0x8,    4, true) \
	TEGRA_FUSE(OPTIN_ENABLE,             "optin_enable",             0x4a8,  4, true) \
	TEGRA_FUSE(PK_H1,                    "pk_h1",                    0x820, 64, true) \
	TEGRA_FUSE(PK_H2,                    "pk_h2",                    0x860, 64, true) \
	TEGRA_FUSE(PUBLIC_KEY_HASH_L,        "public_key_hash_l",        0x64,  32, false) \
	TEGRA_FUSE(PUBLIC_KEY_HASH_R,        "public_key_hash_r",        0x55c, 32, false) \
	TEGRA_FUSE(RESERVED_ODM0,            "reserved_odm0",            0xc8,   4, true) \
	TEGRA_FUSE(RESERVED_ODM1,            "reserved_odm1",            0xcc,   4, true) \
	TEGRA_FUSE(RESERVED_ODM2,            "reserved_odm2",            0xd0,   4, true) \
	TEGRA_FUSE(RESERVED_ODM3,            "reserved_odm3",            0xd4,   4, true) \
	TEGRA_FUSE(RESERVED_ODM4,            "reserved_odm4",            0xd8,   4, true) \
	TEGRA_FUSE(RESERVED_ODM5,            "reserved_odm5",            0xdc,   4, true) \
	TEGRA_FUSE(RESERVED_ODM6,            "reserved_odm6",            0xe0,   4, true) \
	TEGRA_FUSE(RESERVED_ODM7,            "reserved_odm7",            0xe4,   4, true) \
	TEGRA_FUSE(REVOKE_PK_H0,             "revoke_pk_h0",             0x8a0,  4, true) \
	TEGRA_FUSE(REVOKE_PK_H1,             "revoke_pk_h1",             0x8a4,  4, true) \
	TEGRA_FUSE(SECURITY_MODE,            "security_mode",            0xa0,   4, true) \
	TEGRA_FUSE(SYSTEM_FW_FIELD_RATCHET0, "system_fw_field_ratchet0", 0x420,  4, true) \
	TEGRA_FUSE(SYSTEM_FW_FIELD_RATCHET1, "system_fw_field_ratchet1", 0x424,  4, true) \
	TEGRA_FUSE(SYSTEM_FW_FIELD_RATCHET2, "system_fw_field_ratchet2", 0x428,  4, true) \
	TEGRA_FUSE(SYSTEM_FW_FIELD_RATCHET3, "system_fw_field_ratchet3", 0x42c,  4, true)

#define TEGRA_FUSE(x_, y_, z_, a_, b_) TEGRA_FUSE_##x_,
typedef enum {
	TEGRAxxx_FUSES
	TEGRA_FUSE_COUNT__
} tegra_fuse_t;
#undef TEGRA_FUSE
#define TEGRA_FUSE_COUNT ((int) TEGRA_FUSE_COUNT__)


typedef enum {
	TEGRA_SOCTYPE_234,
	TEGRA_SOCTYPE_264,
	TEGRA_SOCTYPE_COUNT__
} tegra_soctype_t;
#define TEGRA_SOCTYPE_COUNT ((int) TEGRA_SOCTYPE_COUNT__)

struct tegra_fusectx_s;
typedef struct tegra_fusectx_s *tegra_fusectx_t;

tegra_fusectx_t tegra_fuse_context_open(const char *basepath);
int tegra_fuse_soctype(tegra_fusectx_t ctx, tegra_soctype_t *soc);
ssize_t tegra_fuse_soctype_name(tegra_fusectx_t ctx, char *buf, size_t bufsiz);
void tegra_fuse_context_close(tegra_fusectx_t ctx);
ssize_t tegra_fuse_read(tegra_fusectx_t ctx, tegra_fuse_t fuseid, void *buf, size_t bufsiz);
ssize_t tegra_fuse_write(tegra_fusectx_t ctx, tegra_fuse_t fuseid, const void *buf, size_t bufsiz);
const char *tegra_fuse_name(tegra_fusectx_t ctx, tegra_fuse_t fuseid);
int tegra_fuse_id(tegra_fusectx_t ctx, const char *fusename, tegra_fuse_t *fuseid);
unsigned int tegra_fuse_count(tegra_fusectx_t ctx);
ssize_t tegra_fuse_size(tegra_fusectx_t ctx, tegra_fuse_t fuseid);
const char *tegra_first_fuse_name(tegra_fusectx_t ctx, void **iter_ctx);
const char *tegra_next_fuse_name(tegra_fusectx_t ctx, void **iter_ctx);

#endif /* tegra_fuse_h__ */
