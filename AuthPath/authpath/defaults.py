"""
"Owner can manage their own resource" defaults - #3 of the usability plan.

Instead of writing every policy by hand, a scenario can declare:

    "policy_defaults": [
      { "resource": "account", "actions": ["read", "update"],
        "admin_roles": ["admin"] }
    ]

which expands into the same Policy objects you would have written yourself:
  - "<resource> owner may <action>"      (resource.owner == subject.id)
  - "<role> may <action> any <resource>" (subject.roles contains that role)

Explicit policies in the scenario are simply added alongside these. Because
the engine combines policies with deny-overrides, a hand-written DENY policy
still overrides a default ALLOW - so defaults only ever grant a *starting*
point; you write exceptions, not everything.
"""

from authpath.models.policy import Policy

DEFAULT_SUBJECT_TYPE = "user"


def expand_policy_defaults(policy_defaults: list[dict]) -> list[Policy]:
    generated = []

    for entry in policy_defaults:
        resource = entry["resource"]
        actions = entry.get("actions", ["read"])
        subject_type = entry.get("subject_type", DEFAULT_SUBJECT_TYPE)
        owner_field = entry.get("owner_field", "resource.owner")
        admin_roles = entry.get("admin_roles", [])

        for action in actions:
            generated.append(Policy(
                id=f"default-owner-{resource}-{action}",
                subject=subject_type, action=action, resource=resource,
                condition={"equals": [owner_field, "subject.id"]},
                decision="allow",
                description=(
                    f"[default] the owner of a {resource} may {action} it"
                ),
            ))

            for role in admin_roles:
                generated.append(Policy(
                    id=f"default-role-{resource}-{action}-{role}",
                    subject=subject_type, action=action, resource=resource,
                    condition={"contains": ["subject.roles", role]},
                    decision="allow",
                    description=(
                        f"[default] role '{role}' may {action} any {resource}"
                    ),
                ))

    return generated
