// SPDX-License-Identifier: GPL-2.0

#ifndef __ASM_MITIGATIONS_H
#define __ASM_MITIGATIONS_H

enum cpu_mitigation_state {
	CPU_MITIGATION_UNKNOWN,
	CPU_MITIGATION_REQUIRED,
	CPU_MITIGATION_UNAFFECTED,
	CPU_MITIGATION_SYSTEM_UNAFFECTED,
};

enum system_mitigation_state {
	SYSTEM_MITIGATION_UNKNOWN,
	SYSTEM_MITIGATION_AFFECTED,
	SYSTEM_MITIGATION_UNAFFECTED,
};

enum policy_mitigation_state {
	POLICY_MITIGATION_OFF,
	POLICY_MITIGATION_ON,
	POLICY_MITIGATION_AUTO,
};

enum cpu_policy_mitigation_state {
	CPU_POLICY_MITIGATION_NONE,
	CPU_POLICY_MITIGATION_OFF,
	CPU_POLICY_MITIGATION_ON,
	CPU_POLICY_MITIGATION_AUTO,
};

struct arm64_mitigation_state {
	enum policy_mitigation_state 		policy;
	enum system_mitigation_state 		system;
	enum cpu_policy_mitigation_state __percpu *pcpu;
	const char				*strings[];
};

enum cpu_policy_mitigation_state
arm64_update_system_mitigation_state(struct arm64_mitigation_state *ms,
				     enum cpu_mitigation_state cms);
const char *arm64_get_mitigation_string(struct arm64_mitigation_state *ms);

#endif
