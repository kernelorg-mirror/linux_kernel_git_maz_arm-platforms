// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 ARM Ltd, All Rights Reserved
 */

#include <linux/percpu.h>

#include <asm/bug.h>
#include <asm/mitigations.h>

enum arm64_workaround_state
arm64_update_system_vulnerability_state(struct arm64_mitigation_state *ms,
					enum arm64_vulnerability_state cvs)
{
	enum arm64_workaround_state cws;

	/*
	 * One-off initialization of the system workaround state based
	 * on the cmdline or default configuration
	 */
	if (ms->system_workaround == __ARM64_WORKAROUND_UNINITIALIZED)
		ms->system_workaround = ms->cmd_line;

	/* Propagate the CPU vulnerability state to the system level */
	switch (cvs) {
	case ARM64_VULNERABILITY_UNKNOWN:
		if (ms->system_vulnerability > ARM64_VULNERABILITY_UNKNOWN)
			ms->system_vulnerability = ARM64_VULNERABILITY_UNKNOWN;
		break;

	case ARM64_VULNERABILITY_AFFECTED:
		if (ms->system_vulnerability > ARM64_VULNERABILITY_AFFECTED)
			ms->system_vulnerability = ARM64_VULNERABILITY_AFFECTED;
		break;

	case ARM64_VULNERABILITY_UNAFFECTED:
		WARN_ON(ms->system_vulnerability != ARM64_VULNERABILITY_UNAFFECTED);
		break;
	}

	/*
	 * If we have an affected system, and yet decided not to
	 * mitigate it, "promote" the system to be vulnerable. In all
	 * the other cases, you get what the system gives you.
	 */
	if (ms->system_workaround == ARM64_WORKAROUND_OFF &&
	    ms->system_vulnerability == ARM64_VULNERABILITY_AFFECTED)
		ms->system_vulnerability = ARM64_VULNERABILITY_UNKNOWN;

	/* Flag out a pathological case -- go fix your FW */
	WARN_ON(ms->system_workaround == ARM64_WORKAROUND_ON &&
		ms->system_vulnerability == ARM64_VULNERABILITY_UNKNOWN);

	/*
	 * If the system as a whole isn't mitigated nor vulnerable,
	 * don't do a thing, and set the workaround to NONE.
	 *
	 * If on the contrary it is affected, set the CPU mitigation
	 * state to the same as the whole system, unless the CPU
	 * itself is unaffected.
	 */
	if (ms->system_vulnerability != ARM64_VULNERABILITY_AFFECTED)
		ms->system_workaround = cws = ARM64_WORKAROUND_NONE;
	else if (cvs != ARM64_VULNERABILITY_UNAFFECTED)
		cws = ms->system_workaround;
	else
		cws = ARM64_WORKAROUND_NONE;

	*this_cpu_ptr(ms->cpu_workaround) = cws;

	return cws;
}

const char *arm64_get_mitigation_string(struct arm64_mitigation_state *ms)
{
	return ms->strings[ms->system_vulnerability];
}
