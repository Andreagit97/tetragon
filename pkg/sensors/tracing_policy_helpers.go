// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"errors"
	"fmt"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/tetragon/pkg/selectors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

// func specHasForEachCgroupFilter(spec v1alpha1.HookSpec) (bool, uint32, error) {
// 	hasForEach := false
// 	argType := uint32(0)
// 	for _, sel := range spec.GetSelectors() {
// 		for _, argSel := range sel.MatchArgs {
// 			ok, ty, err := selectors.ArgSelectorHasForEachCgroup(&argSel, spec.GetArguments())
// 			if err != nil {
// 				return false, 0, err
// 			}
// 			if !ok {
// 				continue
// 			}
// 			if hasForEach {
// 				return false, 0, errors.New("multiple forEachCgroup filters in the same tracing policy are not supported")
// 			}
// 			hasForEach = true
// 			argType = ty
// 		}

// 		// Not supported on return args
// 		for _, argSel := range sel.MatchReturnArgs {
// 			ok, _, err := selectors.ArgSelectorHasForEachCgroup(&argSel, spec.GetArguments())
// 			if err != nil {
// 				return false, 0, err
// 			}
// 			if ok {
// 				return false, 0, errors.New("forEachCgroup filter on return value is not supported")
// 			}
// 		}

// 		ks, ok := spec.(v1alpha1.KProbeSpec)
// 		if !ok {
// 			continue
// 		}
// 		// Only kprobe spec has this

// 		dataArgs := ks.Data
// 		for _, argSel := range sel.MatchData {
// 			ok, ty, err := selectors.ArgSelectorHasForEachCgroup(&argSel, dataArgs)
// 			if err != nil {
// 				return false, 0, err
// 			}
// 			if !ok {
// 				continue
// 			}
// 			if hasForEach {
// 				return false, 0, errors.New("multiple forEachCgroup filters in the same tracing policy are not supported")
// 			}
// 			hasForEach = true
// 			argType = ty
// 		}
// 	}
// 	return hasForEach, argType, nil
// }

// func validateTracingPolicy(tp *v1alpha1.TracingPolicySpec) (bool, uint32, error) {
// 	// Validate that we have at most one section among kprobes, tracepoints, ...
// 	sections := 0
// 	hookSpecs := []v1alpha1.HookSpec{}
// 	if len(tp.KProbes) > 0 {
// 		sections++
// 		for _, s := range tp.KProbes {
// 			hookSpecs = append(hookSpecs, s)
// 		}
// 	}
// 	if len(tp.Tracepoints) > 0 {
// 		sections++
// 		for _, s := range tp.Tracepoints {
// 			hookSpecs = append(hookSpecs, s)
// 		}
// 	}
// 	if len(tp.LsmHooks) > 0 {
// 		sections++
// 		for _, s := range tp.LsmHooks {
// 			hookSpecs = append(hookSpecs, s)
// 		}
// 	}
// 	if len(tp.UProbes) > 0 {
// 		sections++
// 		for _, s := range tp.UProbes {
// 			hookSpecs = append(hookSpecs, s)
// 		}
// 	}
// 	if len(tp.Usdts) > 0 {
// 		sections++
// 		for _, s := range tp.Usdts {
// 			hookSpecs = append(hookSpecs, s)
// 		}
// 	}

// 	// it is possible we don't have any hooks at all
// 	if sections == 0 {
// 		return false, 0, nil
// 	}

// 	if sections > 1 {
// 		return false, 0, errors.New("tracing policies with multiple sections of kprobes, tracepoints, lsm hooks, uprobes or usdts are currently not supported")
// 	}

// 	hasForEach := false
// 	argType := uint32(0)

// 	for _, spec := range hookSpecs {
// 		ok, ty, err := specHasForEachCgroupFilter(spec)
// 		if err != nil {
// 			return false, 0, err
// 		}
// 		if !ok {
// 			continue
// 		}
// 		if hasForEach {
// 			return false, 0, errors.New("multiple forEachCgroup filters in the same tracing policy are not supported")
// 		}
// 		hasForEach = true
// 		argType = ty

// 	}
// 	return hasForEach, argType, nil
// }

// // todo!: extend to tracepoints/uprobes
// values := []string{}
// switch col.forEachCgroupState.SensorName {
// case "generic_kprobe":
// 	// Validation on the structure of the policy
// 	if len(spec.KProbes) != 1 {
// 		return fmt.Errorf("for-each-cgroup-values policies must have exactly one kprobe, got %d", len(spec.KProbes))
// 	}
// 	funcName := spec.KProbes[0].Call
// 	if funcName != col.forEachCgroupState.CallName {
// 		return fmt.Errorf("for-each-cgroup-values policy kprobe function %s does not match referenced policy function %s", funcName, col.forEachCgroupState.CallName)
// 	}
// 	if len(spec.KProbes[0].Selectors) != 1 {
// 		return fmt.Errorf("for-each-cgroup-values policies must have exactly one selector, got %d", len(spec.KProbes[0].Selectors))
// 	}
// 	if len(spec.KProbes[0].Selectors[0].MatchArgs) != 1 {
// 		return fmt.Errorf("for-each-cgroup-values policies must have exactly one match argument, got %d", len(spec.KProbes[0].Selectors[0].MatchArgs))
// 	}
// 	values = spec.KProbes[0].Selectors[0].MatchArgs[0].Values
// 	if len(values) == 0 {
// 		return fmt.Errorf("for-each-cgroup-values policies must provide some values")
// 	}
// default:
// 	return fmt.Errorf("for-each-cgroup-values policies not supported for sensor %s", col.forEachCgroupState.SensorName)
// }

func getNamespaceAndSelectors(tp tracingpolicy.TracingPolicy) (string, *slimv1.LabelSelector, *slimv1.LabelSelector) {
	var namespace string
	if tpNs, ok := tp.(tracingpolicy.TracingPolicyNamespaced); ok {
		namespace = tpNs.TpNamespace()
	}

	var podSelector *slimv1.LabelSelector
	if ps := tp.TpSpec().PodSelector; ps != nil {
		if len(ps.MatchLabels)+len(ps.MatchExpressions) > 0 {
			podSelector = ps
		}
	}

	var containerSelector *slimv1.LabelSelector
	if ps := tp.TpSpec().ContainerSelector; ps != nil {
		if len(ps.MatchLabels)+len(ps.MatchExpressions) > 0 {
			containerSelector = ps
		}
	}
	return namespace, podSelector, containerSelector
}

func specHasForEachCgroupFilter(spec v1alpha1.HookSpec) (bool, error) {
	hasForEach := false
	for _, sel := range spec.GetSelectors() {
		for _, argSel := range sel.MatchArgs {
			ok, _, err := selectors.ArgSelectorHasForEachCgroup(&argSel, spec.GetArguments())
			if err != nil {
				return false, err
			}
			if !ok {
				continue
			}
			if hasForEach {
				return false, errors.New("multiple forEachCgroup filters in the same tracing policy are not supported")
			}
			hasForEach = true
		}

		// Not supported on return args
		for _, argSel := range sel.MatchReturnArgs {
			ok, _, err := selectors.ArgSelectorHasForEachCgroup(&argSel, spec.GetArguments())
			if err != nil {
				return false, err
			}
			if ok {
				return false, errors.New("forEachCgroup filter on return value is not supported")
			}
		}

		ks, ok := spec.(v1alpha1.KProbeSpec)
		if !ok {
			continue
		}

		// Only kprobe spec has MatchData
		dataArgs := ks.Data
		for _, argSel := range sel.MatchData {
			ok, _, err := selectors.ArgSelectorHasForEachCgroup(&argSel, dataArgs)
			if err != nil {
				return false, err
			}
			if !ok {
				continue
			}
			if hasForEach {
				return false, errors.New("multiple forEachCgroup filters in the same tracing policy are not supported")
			}
			hasForEach = true
		}
	}
	return hasForEach, nil
}

func validateTracingPolicy(tp tracingpolicy.TracingPolicy) error {
	tpSpec := tp.TpSpec()
	if tpSpec == nil {
		return errors.New("tracing policy spec is nil")
	}

	/////////////////////////
	// Validate that we have at most one section among kprobes, tracepoints, ...
	/////////////////////////
	sections := 0
	hookSpecs := []v1alpha1.HookSpec{}
	if len(tpSpec.KProbes) > 0 {
		sections++
		for _, s := range tpSpec.KProbes {
			hookSpecs = append(hookSpecs, s)
		}
	}
	if len(tpSpec.Tracepoints) > 0 {
		sections++
		for _, s := range tpSpec.Tracepoints {
			hookSpecs = append(hookSpecs, s)
		}
	}
	if len(tpSpec.LsmHooks) > 0 {
		sections++
		for _, s := range tpSpec.LsmHooks {
			hookSpecs = append(hookSpecs, s)
		}
	}
	if len(tpSpec.UProbes) > 0 {
		sections++
		for _, s := range tpSpec.UProbes {
			hookSpecs = append(hookSpecs, s)
		}
	}
	if len(tpSpec.Usdts) > 0 {
		sections++
		for _, s := range tpSpec.Usdts {
			hookSpecs = append(hookSpecs, s)
		}
	}

	// todo!: sections 0 should be a valid policy
	if sections > 1 {
		return errors.New("tracing policies with multiple sections of kprobes, tracepoints, lsm hooks, uprobes or usdts are currently not supported")
	}

	/////////////////////////
	// Validate forEachCgroup usage
	/////////////////////////
	hasForEach := false
	for _, spec := range hookSpecs {
		ok, err := specHasForEachCgroupFilter(spec)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if hasForEach {
			return fmt.Errorf("multiple forEachCgroup filters in the same tracing policy are not supported")
		}
		hasForEach = true
	}

	if !hasForEach {
		return nil
	}

	/////////////////////////
	// Validate that if forEachCgroup is used, no podSelector/containerSelector/namespace is used
	/////////////////////////
	namespace, podSelector, containerSelector := getNamespaceAndSelectors(tp)
	if namespace != "" || podSelector != nil || containerSelector != nil {
		return errors.New("podSelector, containerSelector or namespace cannot be used in combination with forEachCgroup filter")
	}
	return nil
}

func getRefPolicyFromOptions(opts []v1alpha1.OptionSpec) string {
	for _, opt := range opts {
		if opt.Name == "ref-policy" {
			return opt.Value
		}
	}
	return ""
}

func getForEachCgroupValuesFromOptions(opts []v1alpha1.OptionSpec) string {
	for _, opt := range opts {
		if opt.Name == "for-each-cgroup-values" {
			return opt.Value
		}
	}
	return ""
}

// this is ok for current modified TracingPolicy interface
func isForEachCgroupValues(opts []v1alpha1.OptionSpec) bool {
	return getRefPolicyFromOptions(opts) != "" && getForEachCgroupValuesFromOptions(opts) != ""
}
