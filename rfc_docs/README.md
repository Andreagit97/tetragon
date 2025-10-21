# Possible solutions

## 1

We use 2 new CRDs: ForEachWorkloadPolicy and ForEachWorkloadPolicyValues.

```yaml
apiVersion: cilium.io/v1alpha1
kind: ForEachWorkloadPolicy
metadata:
  name: "block-not-allowed-process"
spec:
  # This is the hook we want to instrument once
  kprobes:
  - call: "security_bprm_creds_for_exec"
    syscall: false
    args:
    - index: 0
      type: "linux_binprm"
    selectors:
    - matchArgs:
      - index: 0 
        operator: "NotEqual" 
        values: [] # we don't set values here
      matchActions:
      - action: Override
        argError: -1
---
apiVersion: cilium.io/v1alpha1
kind: ForEachWorkloadPolicyValues
metadata:
  # we need a way to allow multiple instances of this CR with the same name but for different `ForEachWorkloadPolicy`
  name: "deploy-my-deployment" 
spec:
  # Reference to the policy, probably not ideal to use the name as it is not unique
  refPolicy: "block-not-allowed-process" 
  # Select the pods in the workload
  # The controller must ensure that there are no overlapping podSelectors to avoid ambiguity.
  podSelector:
    matchLabels:
      app: "my-deployment-1"
  # Values
  allowedValues: 
    - "/usr/bin/sleep"
    - "/usr/bin/cat"
    - "/usr/bin/my-server-1"
```

## 2

Use new TracingPolicy fields `enforce-kprobe` and `enforce-kprobe-values` to indicate that these policies are to be enforced for each workload separately.

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "block-not-allowed-process"
spec:
  enforce-kprobe:
  - call: "security_bprm_creds_for_exec"
    syscall: false
    args:
    - index: 0
      type: "linux_binprm"
    selectors:
    - matchArgs:
      - index: 0
        operator: "NotEqual"
        values: []
---
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "deploy-my-deployment" 
spec:
  enforce-kprobe-values:
  - refPolicy: "block-not-allowed-process"
    podSelector:
      matchLabels:
        app: "my-deployment-1"
    values:
      - "/usr/bin/sleep"
      - "/usr/bin/cat"
      - "/usr/bin/my-server-1"
```

## 3

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "block-not-allowed-process"
spec:
  kprobe:
  - call: "security_bprm_creds_for_exec"
    syscall: false
    args:
    - index: 0
      type: "linux_binprm"
    selectors:
    - matchArgs:
      - index: 0
        forEachWorkload: true
        operator: "NotEqual"
        values: []
---
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "block-not-allowed-process-***" 
spec:
  kprobe:
  - refPolicy: "block-not-allowed-process"
    podSelector:
      matchLabels:
        app: "my-deployment-1"
    values:
      - "/usr/bin/sleep"
      - "/usr/bin/cat"
      - "/usr/bin/my-server-1"
```
