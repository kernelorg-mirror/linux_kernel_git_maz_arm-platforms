// SPDX-License-Identifier: GPL-2.0
/*
 * Early cpufeature override framework
 *
 * Copyright (C) 2020 Google LLC
 * Author: Marc Zyngier <maz@kernel.org>
 */

#include <linux/kernel.h>
#include <linux/libfdt.h>

#include <asm/cacheflush.h>
#include <asm/setup.h>

struct ftr_set_desc {
	const char 			*name;
	struct arm64_ftr_override	*override;
	struct {
		const char 		*name;
		u8			shift;
	} 				fields[];
};

static const struct ftr_set_desc * const regs[] __initdata = {
};

static char *cmdline_contains_option(const char *cmdline, const char *option)
{
	char *str = strstr(cmdline, option);

	if ((str == cmdline || (str > cmdline && *(str - 1) == ' ')))
		return str;

	return NULL;
}

static int __init find_field(const char *cmdline,
			     const struct ftr_set_desc *reg, int f, u64 *v)
{
	char buf[256], *str;
	size_t len;

	snprintf(buf, ARRAY_SIZE(buf), "%s.%s=", reg->name, reg->fields[f].name);

	str = cmdline_contains_option(cmdline, buf);
	if (!str)
		return -1;

	str += strlen(buf);
	len = strcspn(str, " ");
	len = min(len, ARRAY_SIZE(buf) - 1);
	strncpy(buf, str, len);
	buf[len] = 0;

	return kstrtou64(buf, 0, v);
}

static void __init match_options(const char *cmdline)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(regs); i++) {
		int f;

		if (!regs[i]->override)
			continue;

		for (f = 0; regs[i]->fields[f].name; f++) {
			u64 v;

			if (find_field(cmdline, regs[i], f, &v))
				continue;

			regs[i]->override->val  |= (v & 0xf) << regs[i]->fields[f].shift;
			regs[i]->override->mask |= 0xfUL << regs[i]->fields[f].shift;
		}
	}
}

static __init void parse_cmdline(void)
{
	if (!IS_ENABLED(CONFIG_CMDLINE_FORCE)) {
		const u8 *prop;
		void *fdt;
		int node;

		fdt = get_early_fdt_ptr();
		if (!fdt)
			goto out;

		node = fdt_path_offset(fdt, "/chosen");
		if (node < 0)
			goto out;

		prop = fdt_getprop(fdt, node, "bootargs", NULL);
		if (!prop)
			goto out;

		match_options(prop);

		if (!IS_ENABLED(CONFIG_CMDLINE_EXTEND))
			return;
	}

out:
	match_options(CONFIG_CMDLINE);
}

void init_shadow_regs(void);
asmlinkage void __init init_feature_override(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(regs); i++) {
		if (regs[i]->override) {
			regs[i]->override->val  = 0;
			regs[i]->override->mask = 0;
		}
	}

	parse_cmdline();

	for (i = 0; i < ARRAY_SIZE(regs); i++) {
		if (regs[i]->override)
			__flush_dcache_area(regs[i]->override,
					    sizeof(*regs[i]->override));
	}
}
