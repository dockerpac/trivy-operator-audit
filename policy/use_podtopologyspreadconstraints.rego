package appshield.kubernetes.SG002

import data.lib.kubernetes
import data.lib.utils

default failTopologySpreadConstraints = false

__rego_metadata__ := {
	"id": "SG002",
	"avd_id": "SG002",
	"title": "PodTopologySpreadConstraints not specified",
	"short_code": "pod-topology",
	"version": "v1.0.0",
	"severity": "CRITICAL",
	"type": "Kubernetes Resiliency Check",
	"description": "Use PodTopologySpreadConstraints to increase resiliency to AZ loss",
	"recommended_actions": "Implement PodTopologySpreadConstraints",
	"url": "",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}


# failTopologySpreadConstraints is true if replicas = 1
failTopologySpreadConstraints {
	not kubernetes.object.spec.template.spec.topologySpreadConstraints
}

deny[res] {
	failTopologySpreadConstraints

	msg := kubernetes.format(sprintf("%s '%s' should implement PodTopologySpreadConstraints", [kubernetes.kind, kubernetes.name]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
