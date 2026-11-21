package defense.llm.authz

default allow := false

deny_reasons contains "Insufficient clearance level" if {
	input.user.clearance < input.document.classification
}

deny_reasons contains "Missing required compartment access" if {
	input.document.compartment not in input.user.compartments
}

deny_reasons contains "Volumetric rate limit exceeded" if {
	limit := object.get(input.config, "max_docs_per_hour", 3)
	count(input.session.recent_docs) >= limit
}

deny_reasons contains "Mosaic Effect aggregation violation detected" if {
	projected_entities := {entity |
		some entity in input.session.accumulated_entities
	} | {entity |
		some entity in input.document.entities
	}

	some forbidden in object.get(input.config, "forbidden_combinations", [])
	every entity in forbidden {
		entity in projected_entities
	}
}

allow if {
	count(deny_reasons) == 0
}
