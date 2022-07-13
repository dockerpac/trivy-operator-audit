package appshield.kubernetes.SG007

import data.lib.kubernetes
import data.lib.utils

default failLivenessProbe = false

__rego_metadata__ := {
	"id": "SG007",
	"avd_id": "SG007",
	"title": "LivenessProbe is not defined",
	"short_code": "liveness-probe",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Kubernetes Resiliency Check",
	"description": "Configuring a LivenessProbe helps Kubernetes to automatically restart applications in deadlock.",
	"recommended_actions": "Configure LivenessProbe in 'containers[].livenessProbe'.",
	"url": "",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# getLivenessProbeContainers returns all containers which have set livenessProbe
getLivenessProbeContainers[container] {
	allContainers := kubernetes.containers[_]
	utils.has_key(allContainers, "livenessProbe")
	container := allContainers.name
}

# getNoLivenessProbeContainers returns all containers which have not set
# livenessProbe
getNoLivenessProbeContainers[container] {
	container := kubernetes.containers[_].name
	not getLivenessProbeContainers[container]
}

# failLivenessProbe is true if containers[].livenessProbe is not set
# for ANY container
failLivenessProbe {
	count(getNoLivenessProbeContainers) > 0
}

deny[res] {
	failLivenessProbe

	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should set 'livenessProbe'", [getNoLivenessProbeContainers[_], kubernetes.kind, kubernetes.name]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
