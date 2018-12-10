/*
 * Copyright (C) 2017 - Columbia University and Linaro Ltd.
 * Author: Jintack Lim <jintack.lim@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/kvm.h>
#include <linux/kvm_host.h>

#include <asm/kvm_emulate.h>
#include <asm/kvm_mmu.h>

int kvm_vcpu_init_nested(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_s2_mmu *tmp;
	int num_mmus;
	int ret = -ENOMEM;

	mutex_lock(&kvm->lock);

	num_mmus = atomic_read(&kvm->online_vcpus) * 2;
	tmp = __krealloc(kvm->arch.nested_mmus,
			 num_mmus * sizeof(*kvm->arch.nested_mmus),
			 GFP_KERNEL | __GFP_ZERO);

	if (tmp) {
		if (tmp != kvm->arch.nested_mmus)
			kfree(kvm->arch.nested_mmus);

		tmp[num_mmus - 1].usage_count = -1;
		ret = kvm_alloc_stage2_pgd(&tmp[num_mmus - 1]);
		if (ret)
			goto out;

		tmp[num_mmus - 2].usage_count = -1;
		ret = kvm_alloc_stage2_pgd(&tmp[num_mmus - 2]);
		if (ret) {
			__kvm_free_stage2_pgd(kvm, &tmp[num_mmus - 1]);
			goto out;
		}

		kvm->arch.nested_mmus_size = num_mmus;
		kvm->arch.nested_mmus = tmp;
		tmp = NULL;
	}

out:
	kfree(tmp);
	mutex_unlock(&kvm->lock);
	return ret;
}

int init_nested_virt(void)
{
	if (cpus_have_const_cap(ARM64_HAS_NESTED_VIRT))
		kvm_info("ARMv8.3 Nested virtualization is supported\n");

	return 0;
}

bool nested_virt_in_use(struct kvm_vcpu *vcpu)
{
	if (cpus_have_const_cap(ARM64_HAS_NESTED_VIRT)
	    && test_bit(KVM_ARM_VCPU_NESTED_VIRT, vcpu->arch.features))
		return true;

	return false;
}

/*
 * Inject wfx to the virtual EL2 if this is not from the virtual EL2 and
 * the virtual HCR_EL2.TWX is set. Otherwise, let the host hypervisor
 * handle this.
 */
int handle_wfx_nested(struct kvm_vcpu *vcpu, bool is_wfe)
{
	u64 hcr_el2 = __vcpu_sys_reg(vcpu, HCR_EL2);

	if (vcpu_mode_el2(vcpu))
		return -EINVAL;

	if ((is_wfe && (hcr_el2 & HCR_TWE)) || (!is_wfe && (hcr_el2 & HCR_TWI)))
		return kvm_inject_nested_sync(vcpu, kvm_vcpu_get_hsr(vcpu));

	return -EINVAL;
}
