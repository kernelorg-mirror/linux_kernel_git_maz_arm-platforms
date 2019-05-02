// SPDX-License-Identifier: GPL-2.0

#ifndef __ASM_MITIGATIONS_H
#define __ASM_MITIGATIONS_H

enum arm64_vulnerability_state {
	/* No information or no workaround */
	ARM64_VULNERABILITY_UNKNOWN,
	/* Affected with a workaround */
	ARM64_VULNERABILITY_AFFECTED,
	/* No workaround needed */
	ARM64_VULNERABILITY_UNAFFECTED,
};

enum arm64_workaround_state {
	/* Internal state, must be zero */
	__ARM64_WORKAROUND_UNINITIALIZED = 0,
	/* No workaround to apply */
	ARM64_WORKAROUND_NONE,
	/* Do not apply workaround */
	ARM64_WORKAROUND_OFF,
	/* Force workaround to be on always */
	ARM64_WORKAROUND_ON,
	/* Apply workaround whenever required */
	ARM64_WORKAROUND_AUTO,
};

struct arm64_mitigation_state {
	enum arm64_workaround_state 		cmd_line;
	enum arm64_vulnerability_state 		system_vulnerability;
	enum arm64_workaround_state 		system_workaround;
	enum arm64_workaround_state __percpu	*cpu_workaround;
	const char				*strings[];
};

enum arm64_workaround_state
arm64_update_system_vulnerability_state(struct arm64_mitigation_state *ms,
					enum arm64_vulnerability_state cvs);
const char *arm64_get_mitigation_string(struct arm64_mitigation_state *ms);

#endif
