// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfilter

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/selectors"
)

type forEachCgroupPolicy struct {
	basePolicy
	tracker *forEachCgroupTracker
}

func (m *state) updateEbpfMaps(forEachCgroupTracker *forEachCgroupPolicy, polID PolicyID, cgroupIDs []CgroupID, subMaps selectors.SelectorStringMaps) error {

	subMaps, err := selectors.ConvertValuesToMaps(values, 3) // todo!: type
	if err != nil {
		return fmt.Errorf("failed to convert values to maps: %w", err)
	}

	var err error

	// Cleanup phase in case of errors
	defer func() {
		if err == nil {
			return
		}

		// Cleanup the workload map entries
		for _, cgID := range cgroupIDs {
			err = forEachCgroupTracker.workloadMap.Delete(cgID)
			if err != nil && err != ebpf.ErrKeyNotExist {
				m.log.Warn("failed to rollback workload map after error", "cgroup_id", cgID, "workload_id", polID, "error", err)
			}
		}

		// Cleanup the cgroup maps entries
		for i := range subMaps {
			err = forEachCgroupTracker.cgroupMaps[i].Delete(polID)
			if err != nil && err != ebpf.ErrKeyNotExist {
				m.log.Warn("failed to rollback cgroup map after error", "cgroup_id", cgroupIDs[i], "workload_id", polID, "error", err)
			}
		}
	}()

	for _, cgID := range cgroupIDs {
		err = forEachCgroupTracker.workloadMap.Update(cgID, polID, ebpf.UpdateNoExist)
		if err == nil {
			continue
		}

		if err == ebpf.ErrKeyExist {
			m.log.Warn("key already exists for cgroup", "cgroup_id", cgID, ". Overriding with workload_id", polID)
			err = forEachCgroupTracker.workloadMap.Update(cgID, polID, 0)
		}

		if err != nil {
			return fmt.Errorf("failed to insert (cgroup_id=%d, workload_id=%d) into workload map: %w", cgID, polID, err)
		}
	}

	// We need to create the inner maps
	for i := range subMaps {
		if len(subMaps[i]) == 0 {
			continue
		}

		mapKeySize := selectors.StringMapsSizes[i]
		if i == 7 && !kernels.MinKernelVersion("5.11") {
			mapKeySize = selectors.StringMapSize7a
		}

		name := fmt.Sprintf("work_%d_map_%d", polID, i)
		innerSpec := &ebpf.MapSpec{
			Name:       name,
			Type:       ebpf.Hash,
			KeySize:    uint32(mapKeySize),
			ValueSize:  uint32(1),
			MaxEntries: uint32(len(subMaps[i])),
		}

		if !kernels.MinKernelVersion("5.9") {
			innerSpec.Flags = uint32(bpf.BPF_F_NO_PREALLOC)
			innerSpec.MaxEntries = uint32(200)
		}

		inner, err := ebpf.NewMap(innerSpec)
		if err != nil {
			return fmt.Errorf("failed to create inner_map: %w", err)
		}
		err = forEachCgroupTracker.cgroupMaps[i].Update(polID, uint32(inner.FD()), ebpf.UpdateNoExist)
		inner.Close()
		if err != nil {
			return fmt.Errorf("failed to insert inner policy (id=%d) map: %w", polID, err)
		}
	}

	return nil
}

func (m *state) getForEachCgroupPolicyTracker(refPolID PolicyID) (*forEachCgroupTracker, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	index := m.findForEachCgroupTrackerIndex(refPolID)
	if index == -1 {
		return nil, fmt.Errorf("forEachCgroup tracker with id %d does not exist", refPolID)
	}
	return m.forEachCgroupTrackers[index], nil
}

func (m *state) AddForEachCgroupPolicy(polID PolicyID, refPolID PolicyID, namespace string, podLabelSelector *slimv1.LabelSelector,
	containerLabelSelector *slimv1.LabelSelector) error {
	tracker, err := m.getForEachCgroupPolicyTracker(refPolID)
	if err != nil {
		return err
	}
	policy := &forEachCgroupPolicy{
		tracker: tracker,
	}
	policy.setID(polID)
	return m.addPolicyCommon(policy, "", podLabelSelector, containerLabelSelector)
}

func (m *state) DeleteForEachCgroupPolicy(polID PolicyID) error {
	return m.delPolicyCommon(polID)
}

func (pol *forEachCgroupPolicy) addCgroupIDs(log *slog.Logger, ids []CgroupID) error {
	var err error
	workloadMap := pol.tracker.workloadMap
	if workloadMap == nil {
		return fmt.Errorf("workload map is nil for forEachCgroupPolicy with id %d", pol.getID())
	}

	// Cleanup of the maps if something goes wrong
	defer func() {
		if err == nil {
			return
		}

		for _, id := range ids {
			err = workloadMap.Delete(id)
			if err != nil && errors.Is(err, ebpf.ErrKeyNotExist) {
				log.Warn("failed to rollback workload map after error", "cgroup_id", id, "workload_id", pol.getID(), "error", err)
			}
		}
	}()

	for _, id := range ids {
		err = workloadMap.Update(id, pol.getID(), ebpf.UpdateNoExist)
		if err == nil {
			continue
		}

		if errors.Is(err, ebpf.ErrKeyExist) {
			log.Warn("key already exists for cgroup", "cgroup_id", id, ". Overriding with workload_id", pol.getID())
			err = workloadMap.Update(id, pol.getID(), 0)
		}

		if err != nil {
			return fmt.Errorf("failed to insert (cgroup_id=%d, workload_id=%d) into workload map: %w", id, pol.getID(), err)
		}
	}
	return nil
}

func (pol *forEachCgroupPolicy) AddInitialCgroupIDs(state *state, ids []CgroupID) error {
	return pol.addCgroupIDs(state.log, ids)
}

func (pol *forEachCgroupPolicy) AddCgroupIDs(log *slog.Logger, ids []CgroupID) error {
	return pol.addCgroupIDs(log, ids)
}

func (pol *forEachCgroupPolicy) DelCgroupIDs(log *slog.Logger, ids []CgroupID) error {
	workloadMap := pol.tracker.workloadMap
	if workloadMap == nil {
		return fmt.Errorf("workload map is nil for forEachCgroupPolicy with id %d", pol.getID())
	}

	for _, id := range ids {
		err := workloadMap.Delete(id)
		if err != nil && errors.Is(err, ebpf.ErrKeyNotExist) {
			log.Warn("failed to remove entry from workload map", "cgroup_id", id, "workload_id", pol.getID(), "error", err)
		}
	}
	return nil
}

func (pol *forEachCgroupPolicy) Close(log *slog.Logger) {
	var cgroupID uint64
	var policyID uint32
	currPolicyID := pol.getID()
	workloadIterator := pol.tracker.workloadMap.Iterate()
	for workloadIterator.Next(&cgroupID, &policyID) {
		if PolicyID(policyID) == currPolicyID {
			if err := pol.tracker.workloadMap.Delete(cgroupID); err != nil {
				log.Warn("failed to delete cgroupID from workload map during forEachCgroupPolicy Close", "cgroup_id", cgroupID, "workload_id", currPolicyID, "error", err)
			}
		}
	}

	if err := workloadIterator.Err(); err != nil {
		log.Warn("failed to iterate over workload map during forEachCgroupPolicy Close", "error", err)
	}
}
