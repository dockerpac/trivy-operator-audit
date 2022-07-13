package appshield.kubernetes.SG001

import data.lib.kubernetes
import data.lib.utils

default failNumberReplicas = false

__rego_metadata__ := {
	"id": "SG001",
	"avd_id": "SG001",
	"title": "Only 1 replica",
	"short_code": "one-replica",
	"version": "v1.0.0",
	"severity": "CRITICAL",
	"type": "Kubernetes Resiliency Check",
	"description": "Use more than 1 replica when possible to increase resiliency.",
	"recommended_actions": "Set replicas=2 when possible.",
	"url": "test",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}


# failNumberReplicas is true if replicas = 1
failNumberReplicas {
	kubernetes.object.spec.replicas == 1
}

deny[res] {
	failNumberReplicas

	msg := kubernetes.format(sprintf("%s '%s' should use more than 1 replica when possible", [kubernetes.kind, kubernetes.name]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
