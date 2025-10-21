// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"errors"
	"fmt"
	"path"

	api "github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/eventhandler"
	gt "github.com/cilium/tetragon/pkg/generictypes"
	"github.com/cilium/tetragon/pkg/idtable"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/selectors"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	lru "github.com/hashicorp/golang-lru/v2"
)

const (
	enforcerElfName = "bpf_enforcer_skeleton.o"
)

var (
	// genericKprobeTable is a global table that maintains information for generic kprobes
	enforcerSkeletonTable idtable.Table
)

// internal enforcerSkeleton info
type enforcerSkeleton struct {
	loadArgs          kprobeLoadArgs
	argSigPrinters    []argPrinter
	argReturnPrinters []argPrinter
	funcName          string
	instance          int

	// for kprobes that have a retprobe, we maintain the enter events in
	// the map, so that we can merge them when the return event is
	// generated. The events are maintained in the map below, using
	// the retprobe_id (thread_id) and the enter ktime as the key.
	pendingEvents *lru.Cache[pendingEventKey, pendingEvent]

	tableId idtable.EntryID

	// for kprobes that have a GetUrl or DnsLookup action, we store the table of arguments.
	actionArgs idtable.Table

	// policyName is the name of the policy that this tracepoint belongs to
	policyName string

	// message field of the Tracing Policy
	message string

	// tags field of the Tracing Policy
	tags []string

	// is there override defined for the kprobe
	hasOverride bool

	// Does this kprobe is using stacktraces? Note that as specified in the
	// above data field comment, the map is global for multikprobe and unique
	// for each kprobe when using single kprobes.
	hasStackTrace bool

	customHandler eventhandler.Handler
}

func enforcerSkeletonTableGet(id idtable.EntryID) (*enforcerSkeleton, error) {
	entry, err := enforcerSkeletonTable.GetEntry(id)
	if err != nil {
		return nil, fmt.Errorf("getting entry from enforcerSkeletonTable failed with: %w", err)
	}
	val, ok := entry.(*enforcerSkeleton)
	if !ok {
		return nil, fmt.Errorf("getting entry from enforcerSkeletonTable failed with: got invalid type: %T (%v)", entry, entry)
	}
	return val, nil
}

func (e *enforcerSkeleton) SetID(id idtable.EntryID) {
	e.tableId = id
}

func addEnforcerSkeleton(funcName string, f *v1alpha1.KProbeSpec) (id idtable.EntryID, err error) {
	var argSigPrinters []argPrinter
	var argReturnPrinters []argPrinter
	var setRetprobe bool
	var allBTFArgs [api.EventConfigMaxArgs][api.MaxBTFArgDepth]api.ConfigBTFArg

	errFn := func(err error) (idtable.EntryID, error) {
		return idtable.UninitializedEntryID, err
	}

	if f == nil {
		return errFn(errors.New("error adding kprobe, the kprobe spec is nil"))
	}

	if !bpf.HasModifyReturn() {
		return errFn(errors.New("error: the skeleton requires fmodret support"))
	}

	// todo!: evaluate if we need large progs
	// if !config.EnableLargeProgs() {
	// 	return errFn(errors.New("ForEachWorkload requires kernel >=5.3"))
	// }

	// todo!: evaluate if we want only security_hooks for the first implementation

	eventConfig := initEventConfig()
	// We don't need the ID of the policy here.
	eventConfig.PolicyID = 0
	// We don't need the return value here.
	eventConfig.ArgReturn = int32(0)
	// We don't need syscall here.
	eventConfig.Syscall = 0

	addArg := func(j int, a *v1alpha1.KProbeArg, data bool) error {
		// First try userspace types
		var argType int
		userArgType := gt.GenericUserTypeFromString(a.Type)

		if userArgType != gt.GenericInvalidType {
			// This is a userspace type, map it to kernel type
			argType = gt.GenericUserToKernelType(userArgType)
		} else {
			argType = gt.GenericTypeFromString(a.Type)
		}

		if a.Resolve != "" && j < api.EventConfigMaxArgs {
			if !bpf.HasProgramLargeSize() {
				return errors.New("error: Resolve flag can't be used for your kernel version. Please update to version 5.4 or higher or disable Resolve flag")
			}
			lastBTFType, btfArg, err := resolveBTFArg(f.Call, a, false)
			if err != nil {
				return fmt.Errorf("error on hook %q for index %d : %w", f.Call, a.Index, err)
			}
			allBTFArgs[j] = btfArg
			argType = findTypeFromBTFType(a, lastBTFType)
		}

		if argType == gt.GenericInvalidType {
			return fmt.Errorf("Arg(%d) type '%s' unsupported", j, a.Type)
		}

		if a.MaxData {
			if argType != gt.GenericCharBuffer {
				logger.GetLogger().Warn("maxData flag is ignored (supported for char_buf type)")
			}
			if !config.EnableLargeProgs() {
				logger.GetLogger().Warn("maxData flag is ignored (supported from large programs)")
			}
		}
		argMValue, err := getMetaValue(a)
		if err != nil {
			return err
		}
		if a.Index > 4 {
			return fmt.Errorf("error add arg: ArgType %s Index %d out of bounds",
				a.Type, int(a.Index))
		}
		eventConfig.BTFArg = allBTFArgs
		eventConfig.ArgType[j] = int32(argType)
		eventConfig.ArgMeta[j] = uint32(argMValue)
		eventConfig.ArgIndex[j] = int32(a.Index)

		argP := argPrinter{
			index:    int(a.Index),
			ty:       argType,
			userType: userArgType,
			maxData:  a.MaxData,
			label:    a.Label,
			data:     data,
		}
		argSigPrinters = append(argSigPrinters, argP)

		pathArgWarning(a.Index, argType, f.Selectors)
		return nil
	}

	if len(f.Args) > api.EventConfigMaxArgs {
		return errFn(fmt.Errorf("too many arguments, max %d: args(%d)", api.EventConfigMaxArgs, len(f.Args)))
	}

	var j int

	// Parse Arguments
	for _, arg := range f.Args {
		if arg.Source != "" {
			return errFn(fmt.Errorf("standard argument is not allowed to have source configured, current value: '%s'", arg.Source))
		}
		if err := addArg(j, &arg, false); err != nil {
			return errFn(err)
		}
		j = j + 1
	}

	enforcerEntry := enforcerSkeleton{
		loadArgs: kprobeLoadArgs{
			retprobe: false,
			syscall:  false,
			config:   eventConfig,
		},
		argSigPrinters:    argSigPrinters,
		argReturnPrinters: argReturnPrinters,
		// this is the name of kernel function to attach to
		funcName:      funcName,
		instance:      0, // instance is hardcoded to 0 because forEachWorkload skeleton can have only one kprobe
		pendingEvents: nil,
		tableId:       idtable.UninitializedEntryID,
		policyName:    "", // todo!: see what we want to do here.
		// so far it is always true but it really depends on how much we want to extend the syntax
		// we set it to false because we want a real unique fmod_ret.
		hasOverride: false,
		customHandler: func(e []observer.Event, err error) ([]observer.Event, error) {
			return e, err
		}, // todo!: double check this custom handler
		message: "",         // todo!: not supported for now
		tags:    []string{}, // todo!: not supported for now
		// so far it is always false
		hasStackTrace: selectors.HasStackTrace(f.Selectors),
	}

	var maps *selectors.KernelSelectorMaps
	// Parse Filters into kernel filter logic
	enforcerEntry.loadArgs.selectors.entry, err = selectors.InitKernelSelectorState(f.Selectors, f.Args, f.Data, &enforcerEntry.actionArgs, nil, maps)
	if err != nil {
		return errFn(err)
	}

	// not sure what is it.
	enforcerEntry.pendingEvents, err = lru.New[pendingEventKey, pendingEvent](4096)
	if err != nil {
		return errFn(err)
	}

	enforcerSkeletonTable.AddEntry(&enforcerEntry)
	// to understand if we need it
	eventConfig.FuncId = uint32(enforcerEntry.tableId.ID)

	logger.GetLogger().
		Info("Added kprobe", "return", setRetprobe, "function", enforcerEntry.funcName, "override", enforcerEntry.hasOverride)

	return enforcerEntry.tableId, nil
}

func createEnforcerSensorFromEntry(polInfo *policyInfo, enforcerEntry *enforcerSkeleton,
	progs []*program.Program, maps []*program.Map, has hasMaps) ([]*program.Program, []*program.Map) {
	loadProgName := enforcerElfName

	pinProg := enforcerEntry.funcName

	load := program.Builder(
		path.Join(option.Config.HubbleLib, loadProgName),
		pinProg,
		"fmod_ret/enforcer_skeleton",
		pinProg,
		"enforcer_skeleton").
		SetLoaderData(enforcerEntry.tableId).
		SetPolicy(enforcerEntry.policyName)
	progs = append(progs, load)

	// do we need it ?????
	configMap := program.MapBuilderProgram("config_map", load)
	maps = append(maps, configMap)

	tailCalls := program.MapBuilderProgram("kprobe_calls", load)
	maps = append(maps, tailCalls)

	filterMap := program.MapBuilderProgram("filter_map", load)
	maps = append(maps, filterMap)

	maps = append(maps, filterMaps(load, enforcerEntry)...)

	retProbe := program.MapBuilderSensor("retprobe_map", load)
	maps = append(maps, retProbe)

	callHeap := program.MapBuilderSensor("process_call_heap", load)
	maps = append(maps, callHeap)

	selMatchBinariesMap := program.MapBuilderProgram("tg_mb_sel_opts", load)
	maps = append(maps, selMatchBinariesMap)

	matchBinariesPaths := program.MapBuilderProgram("tg_mb_paths", load)
	if !kernels.MinKernelVersion("5.9") {
		// Versions before 5.9 do not allow inner maps to have different sizes.
		// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
		matchBinariesPaths.SetInnerMaxEntries(enforcerEntry.loadArgs.selectors.entry.MatchBinariesPathsMaxEntries())
	}
	maps = append(maps, matchBinariesPaths)

	maps = append(maps, polInfo.policyConfMap(load), polInfo.policyStatsMap(load))

	logger.GetLogger().Info(fmt.Sprintf("Added generic kprobe sensor: %s -> %s", load.Name, load.Attach),
		"override", enforcerEntry.hasOverride)
	return progs, maps
}

func createEnforcerSensor(polInfo *policyInfo, id idtable.EntryID) ([]*program.Program, []*program.Map, error) {
	var progs []*program.Program
	var maps []*program.Map

	es, err := enforcerSkeletonTableGet(id)
	if err != nil {
		return nil, nil, err
	}

	progs, maps = createEnforcerSensorFromEntry(polInfo, es, progs, maps, has)

	return progs, maps, nil
}

func createGenericEnforcerSensor(
	spec *v1alpha1.TracingPolicySpec,
	name string,
	polInfo *policyInfo,
	valInfo []*kpValidateInfo,
) (*sensors.Sensor, error) {
	var progs []*program.Program
	var maps []*program.Map

	kprobes := spec.KProbes
	if len(kprobes) != 1 {
		return nil, errors.New("forEachWorkload skeleton must have exactly one kprobe")
	}
	syscall := valInfo[0].syscall
	if syscall {
		return nil, errors.New("forEachWorkload skeleton kprobe cannot be a syscall")
	}
	sym := valInfo[0].calls

	id, err := addEnforcerSkeleton(sym[0], &kprobes[0])
	if err != nil {
		return nil, err
	}

	// todo!: still miss this part...
	progs, maps, err = createEnforcerSensor(polInfo, id)
	if err != nil {
		return nil, err
	}

	return &sensors.Sensor{
		Name:      name,
		Progs:     progs,
		Maps:      maps,
		Policy:    polInfo.name,
		Namespace: polInfo.namespace,
		DestroyHook: func() error {
			var errs error

			for _, id := range ids {
				gk, err := genericKprobeTableGet(id)
				if err != nil {
					errs = errors.Join(errs, err)
					continue
				}

				if err = selectors.CleanupKernelSelectorState(gk.loadArgs.selectors.entry); err != nil {
					errs = errors.Join(errs, err)
				}

				_, err = genericKprobeTable.RemoveEntry(id)
				if err != nil {
					errs = errors.Join(errs, err)
				}
			}
			return errs
		},
	}, nil
}

// This is the equivalent of PolicyHandler for this new policy
func PolicyHandlerEnforcer(policy tracingpolicy.TracingPolicy) (sensors.SensorIface, error) {
	spec := policy.TpSpec()
	if len(spec.KProbes) != 1 {
		return nil, errors.New("tracing policies with multiple sections of kprobes are currently not supported")
	}

	log := logger.GetLogger().With(
		"policy", tracingpolicy.TpLongname(policy),
		"sensor", "enforcer_skeleton",
	)
	validateInfo, err := preValidateKprobes(log, spec.KProbes, spec.Lists, spec.Enforcers)
	if err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}
	// if all kprobes where ignored, do not load anything. This is equivalent with
	// having a policy with an empty kprobe: section
	if allKprobesIgnored(validateInfo) {
		return nil, nil
	}
	return createGenericEnforcerSensor(spec, tracingpolicy.TpLongname(policy), nil, validateInfo)
}
