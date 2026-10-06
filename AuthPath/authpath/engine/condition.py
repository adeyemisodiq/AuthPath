from authpath.models.subject import Subject
from authpath.models.resource import Resource

# A string operand starting with one of these is a *path* into the
# subject/resource. Anything else is a literal value.
PATH_PREFIXES = ("subject.", "resource.")


def resolve_value(path: str, subject: Subject, resource: Resource):
    """
    Resolve a policy value path into an actual value.
    """

    if path == "subject.id":
        return subject.id

    if path == "subject.type":
        return subject.type

    if path == "subject.roles":
        return subject.roles

    if path.startswith("subject.attributes."):
        attribute = path.split(".", 2)[2]
        return subject.attributes.get(attribute)

    if path == "resource.id":
        return resource.id

    if path == "resource.type":
        return resource.type

    if path == "resource.owner":
        return resource.owner

    if path.startswith("resource.attributes."):
        attribute = path.split(".", 2)[2]
        return resource.attributes.get(attribute)

    if path.startswith("resource.relationships."):
        relationship = path.split(".", 2)[2]
        return resource.relationships.get(relationship)

    raise ValueError(f"Unsupported value path: {path}")


def resolve_operand(operand, subject: Subject, resource: Resource):
    """Resolve a path operand; pass literals (lists, numbers, ...) through."""

    if isinstance(operand, str) and operand.startswith(PATH_PREFIXES):
        return resolve_value(operand, subject, resource)

    return operand


def _member_of(value, values) -> bool:
    """
    'value in values', where value may itself be a list (e.g. subject.roles).
    A list matches if ANY of its members is in values.

    (Bug fixed: the old code did `value in values` directly, so a list of
    roles was compared against the values as ONE element and never matched.)
    """

    if values is None:
        return False

    if isinstance(value, (list, tuple, set)):
        return any(item in values for item in value)

    return value in values


def evaluate_condition(
    condition: dict,
    subject: Subject,
    resource: Resource
) -> bool:

    if not isinstance(condition, dict) or len(condition) != 1:
        raise ValueError(
            "A condition must be a dict with exactly one operator, "
            f"got: {condition!r}"
        )

    operator, argument = next(iter(condition.items()))

    def value_of(operand):
        return resolve_operand(operand, subject, resource)

    if operator == "equals":
        left, right = argument
        return value_of(left) == value_of(right)

    if operator == "not_equals":
        left, right = argument
        return value_of(left) != value_of(right)

    if operator == "in":
        operand, values = argument
        return _member_of(value_of(operand), value_of(values))

    if operator == "not_in":
        operand, values = argument
        return not _member_of(value_of(operand), value_of(values))

    if operator == "contains":
        container, item = argument
        collection = value_of(container)

        if not isinstance(collection, (list, tuple, set)):
            return False

        return value_of(item) in collection

    if operator == "exists":
        return value_of(argument) is not None

    if operator == "all":
        return all(
            evaluate_condition(item, subject, resource)
            for item in argument
        )

    if operator == "any":
        return any(
            evaluate_condition(item, subject, resource)
            for item in argument
        )

    raise ValueError(f"Unsupported condition operator: {operator!r}")
