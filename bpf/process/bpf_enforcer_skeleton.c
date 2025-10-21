// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"
#include "policy_filter.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64); // cgroup id
	__type(value, u64); // policy id
} filters_map SEC(".maps");

__attribute__((section(("fmod_ret/enforcer_skeleton")), used)) int
generic_fmodret_enforcer_skeleton(struct pt_regs *ctx)
{
	__u64 cgroupid = tg_get_current_cgroup_id();
	if (!cgroupid) {
		// TODO: probably we need some metrics here
		return 0;
	}

	__u64 trackerid = cgrp_get_tracker_id(cgroupid);
	if (trackerid) {
		cgroupid = trackerid;
	}

	__u64 *policy_id = map_lookup_elem(&filters_map, &cgroupid);
	// this will be the index used to access the right string map
	// if there is no policy, it means we don't have to enforce anything for that cgroup.
	if (!policy_id) {
		return 0;
	}

    // Get the argument from the map... all the selector stuff


    // use the correct string hash map according to the policy id


	return 0;
}
