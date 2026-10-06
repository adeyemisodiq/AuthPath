from urllib.parse import quote

VALID_LEVELS = ("object", "function")


class APIBinding:
    """
    Maps an abstract (action, resource type) pair onto a real HTTP endpoint.

    authorization_level:
        "object"   - the check depends on WHICH object is touched (BOLA/IDOR)
        "function" - the check depends on WHAT operation is called (BFLA)
    """

    def __init__(
        self,
        id: str,
        action: str,
        resource: str,
        method: str,
        path: str,
        resource_id_parameter: str | None = None,
        body: dict | None = None,
        authorization_level: str = "object"
    ):
        if authorization_level not in VALID_LEVELS:
            raise ValueError(
                f"Binding {id!r}: authorization_level must be one of "
                f"{VALID_LEVELS}, got {authorization_level!r}"
            )

        self.id = id
        self.action = action
        self.resource = resource
        self.method = method.upper()
        self.path = path
        self.resource_id_parameter = resource_id_parameter
        self.body = body
        self.authorization_level = authorization_level

    def build_path(self, resource_id: str) -> str:
        """Fill the resource-id placeholder (URL-encoded)."""

        if self.resource_id_parameter is None:
            return self.path

        placeholder = "{" + self.resource_id_parameter + "}"

        if placeholder not in self.path:
            raise ValueError(
                f"Binding {self.id!r}: path {self.path!r} has no "
                f"placeholder {placeholder!r}"
            )

        return self.path.replace(placeholder, quote(resource_id, safe=""))

    def __repr__(self):
        return (
            f"APIBinding("
            f"id={self.id!r}, "
            f"action={self.action!r}, "
            f"resource={self.resource!r}, "
            f"method={self.method!r}, "
            f"path={self.path!r}, "
            f"resource_id_parameter={self.resource_id_parameter!r}, "
            f"authorization_level={self.authorization_level!r}"
            f")"
        )
