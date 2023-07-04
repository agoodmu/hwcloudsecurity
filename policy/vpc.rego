package vpc.ID001

import future.keywords.every
import future.keywords.in

__rego_metadata__ := {
	"id": "ID001",
	"title": "Disabled VPC CIDR",
	"severity": "CRITICAL",
	"type": "HCL Custom Check",
}

__rego_input__ := {"selector": [{"type": "terraform"}]}

ForbiddenCIDR := ["10.0.0.0/16","10.10.0.0/16","10.100.0.0/16"]

deny[msg] {
	every vpc in input.resource.huaweicloud_vpc[_] {
		vpc.cidr in ForbiddenCIDR
	}
}