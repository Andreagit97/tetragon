// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfilter

import (
	"fmt"

	"github.com/cilium/ebpf"
)

type forEachCgroupTracker struct {
	// todo!: ideally we should give this another meaning not policyID since this is not a real policy
	// maybe we can use a trackerID or something like that.
	id          PolicyID
	workloadMap *ebpf.Map
}

func (m *state) findForEachCgroupTrackerIndex(polID PolicyID) int32 {
	for i, info := range m.forEachCgroupTrackers {
		if info.id == polID {
			return int32(i)
		}
	}
	return -1
}

func (m *state) AddForEachCgroupTracker(polID PolicyID, workloadMap *ebpf.Map) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.findForEachCgroupTrackerIndex(polID) != -1 {
		return fmt.Errorf("forEachCgroup info with id %d already exists: not adding new one", polID)
	}

	info := &forEachCgroupTracker{
		id:          polID,
		workloadMap: workloadMap,
	}

	m.forEachCgroupTrackers = append(m.forEachCgroupTrackers, info)
	return nil
}

func (m *state) DeleteForEachCgroupTracker(polID PolicyID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	index := m.findForEachCgroupTrackerIndex(polID)
	if index == -1 {
		return fmt.Errorf("forEachCgroup info with id %d does not exist: not deleting", polID)
	}

	// delete all policies associated with this forEachCgroupTracker
	for i := range m.policies {
		pol, ok := m.policies[i].(*forEachCgroupPolicy)
		if !ok {
			continue
		}
		if pol.tracker.id != polID {
			continue
		}

		m.log.Warn("Deleting policy", pol.getID(), "because its parent forEachCgroup with id", polID, "was deleted")
		m.policies = append(m.policies[:i], m.policies[i+1:]...)
	}

	// todo!: check if we need to do something else
	// should we use `release` instead of `Close`?
	m.forEachCgroupTrackers[index].workloadMap.Close()
	m.forEachCgroupTrackers = append(m.forEachCgroupTrackers[:index], m.forEachCgroupTrackers[index+1:]...)
	return nil
}
