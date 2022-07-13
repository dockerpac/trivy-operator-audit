package appshield.kubernetes.SG008

import data.lib.kubernetes
import data.lib.utils

default failReadinessProbe = false

__rego_metadata__ := {
	"id": "SG008",
	"avd_id": "SG008",
	"title": "ReadinessProbe is not defined",
	"short_code": "readiness-probe",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Kubernetes Resiliency Check",
	"description": "Configuring a ReadinessProbe helps Kubernetes to send traffic only to Pods Ready to serve requests.",
	"recommended_actions": "Configure ReadinessProbe in 'containers[].readinessProbe'.",
	"url": "",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# getReadinessProbeContainers returns all containers which have set readinessProbe
getReadinessProbeContainers[container] {
	allContainers := kubernetes.containers[_]
	utils.has_key(allContainers, "readinessProbe")
	container := allContainers.name
}

# getNoReadinessProbeContainers returns all containers which have not set
# readinessProbe
getNoReadinessProbeContainers[container] {
	container := kubernetes.containers[_].name
	not getReadinessProbeContainers[container]
}

# failReadinessProbe is true if containers[].readinessProbe is not set
# for ANY container
failReadinessProbe {
	count(getNoReadinessProbeContainers) > 0
}

deny[res] {
	failReadinessProbe

	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should set 'readinessProbe'", [getNoReadinessProbeContainers[_], kubernetes.kind, kubernetes.name]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
