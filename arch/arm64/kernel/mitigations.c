// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 ARM Ltd, All Rights Reserved
 */

#include <linux/percpu.h>

#include <asm/bug.h>
#include <asm/mitigations.h>

enum cpu_policy_mitigation_state
arm64_update_system_mitigation_state(struct arm64_mitigation_state *ms,
				     enum cpu_mitigation_state cms)
{
	enum cpu_policy_mitigation_state cpms;

	switch (cms) {
	case CPU_MITIGATION_UNKNOWN:
		if (ms->system > SYSTEM_MITIGATION_UNKNOWN)
			ms->system = SYSTEM_MITIGATION_UNKNOWN;
		break;

	case CPU_MITIGATION_REQUIRED:
		if (ms->system > SYSTEM_MITIGATION_AFFECTED)
			ms->system = SYSTEM_MITIGATION_AFFECTED;
		break;

	case CPU_MITIGATION_UNAFFECTED:
		break;

	case CPU_MITIGATION_SYSTEM_UNAFFECTED:
		WARN_ON(ms->system != SYSTEM_MITIGATION_UNAFFECTED);
		break;
	}

	/*
	 * If we have an affected system, and yet decided not to
	 * mitigate it, "promote" the system to be vulnerable. In all
	 * the other cases, you get what the system gives you.
	 */
	if (ms->policy == POLICY_MITIGATION_OFF &&
	    ms->system == SYSTEM_MITIGATION_AFFECTED)
		ms->system = SYSTEM_MITIGATION_UNKNOWN;

	/* Flag out a pathological case -- go fix your FW */
	WARN_ON(ms->policy == POLICY_MITIGATION_ON &&
		ms->system == SYSTEM_MITIGATION_UNKNOWN);

	/* If UNKNOWN or UNAFFECTED, nothing to do */
	if (ms->system != SYSTEM_MITIGATION_AFFECTED) {
		cpms = CPU_POLICY_MITIGATION_NONE;
		goto out;
	}

	switch (ms->policy) {
	case POLICY_MITIGATION_OFF:
		cpms = CPU_POLICY_MITIGATION_OFF;
		break;

	case POLICY_MITIGATION_ON:
		cpms = CPU_POLICY_MITIGATION_ON;
		break;

	case POLICY_MITIGATION_AUTO:
	default:
		cpms = CPU_POLICY_MITIGATION_AUTO;
	}

out:
	*this_cpu_ptr(ms->pcpu) = cpms;

	return cpms;
}

const char *arm64_get_mitigation_string(struct arm64_mitigation_state *ms)
{
	return ms->strings[ms->system];
}
