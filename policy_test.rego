package defense.llm.authz

test_allows_authorized_request if {
	decision := data.defense.llm.authz with input as {
		"user": {
			"user_id": "MIL-9001",
			"role": "military",
			"clearance": 3,
			"compartments": ["FACILITY_ALPHA"],
		},
		"document": {
			"doc_id": "DOC-101",
			"classification": 2,
			"compartment": "FACILITY_ALPHA",
			"entities": ["ALPHA_COORDS"],
		},
		"session": {
			"recent_docs": [],
			"accumulated_entities": [],
		},
		"config": {
			"max_docs_per_hour": 3,
			"forbidden_combinations": [["ALPHA_COORDS", "ALPHA_SCHEDULE"]],
		},
	}

	decision.allow
	count(decision.deny_reasons) == 0
}

test_denies_insufficient_clearance if {
	decision := data.defense.llm.authz with input as {
		"user": {"clearance": 2, "compartments": ["WEAPON_VALKYRIE"]},
		"document": {"classification": 3, "compartment": "WEAPON_VALKYRIE", "entities": ["VALKYRIE_SPECS"]},
		"session": {"recent_docs": [], "accumulated_entities": []},
		"config": {"max_docs_per_hour": 3, "forbidden_combinations": []},
	}

	not decision.allow
	"Insufficient clearance level" in decision.deny_reasons
}

test_denies_missing_compartment if {
	decision := data.defense.llm.authz with input as {
		"user": {"clearance": 3, "compartments": ["FACILITY_ALPHA"]},
		"document": {"classification": 2, "compartment": "WEAPON_VALKYRIE", "entities": ["VALKYRIE_SPECS"]},
		"session": {"recent_docs": [], "accumulated_entities": []},
		"config": {"max_docs_per_hour": 3, "forbidden_combinations": []},
	}

	not decision.allow
	"Missing required compartment access" in decision.deny_reasons
}

test_denies_volumetric_rate_limit if {
	decision := data.defense.llm.authz with input as {
		"user": {"clearance": 3, "compartments": ["FACILITY_ALPHA"]},
		"document": {"classification": 2, "compartment": "FACILITY_ALPHA", "entities": ["ALPHA_COORDS"]},
		"session": {"recent_docs": ["DOC-1", "DOC-2", "DOC-3"], "accumulated_entities": []},
		"config": {"max_docs_per_hour": 3, "forbidden_combinations": []},
	}

	not decision.allow
	"Volumetric rate limit exceeded" in decision.deny_reasons
}

test_denies_mosaic_aggregation if {
	decision := data.defense.llm.authz with input as {
		"user": {"clearance": 3, "compartments": ["FACILITY_ALPHA"]},
		"document": {"classification": 2, "compartment": "FACILITY_ALPHA", "entities": ["ALPHA_SCHEDULE"]},
		"session": {"recent_docs": ["DOC-101"], "accumulated_entities": ["ALPHA_COORDS"]},
		"config": {
			"max_docs_per_hour": 3,
			"forbidden_combinations": [["ALPHA_COORDS", "ALPHA_SCHEDULE"]],
		},
	}

	not decision.allow
	"Mosaic Effect aggregation violation detected" in decision.deny_reasons
}

test_allows_below_rate_limit if {
	decision := data.defense.llm.authz with input as {
		"user": {"clearance": 2, "compartments": ["FACILITY_ALPHA"]},
		"document": {"classification": 2, "compartment": "FACILITY_ALPHA", "entities": ["ALPHA_COORDS"]},
		"session": {"recent_docs": ["DOC-101", "DOC-102"], "accumulated_entities": ["ALPHA_COORDS"]},
		"config": {
			"max_docs_per_hour": 3,
			"forbidden_combinations": [["ALPHA_COORDS", "ALPHA_SCHEDULE"]],
		},
	}

	decision.allow
}
