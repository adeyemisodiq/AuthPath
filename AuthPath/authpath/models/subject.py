class Subject:
    def __init__(
        self,
        id: str,
        type: str = "user",
        roles: list[str] | None = None,
        attributes: dict[str, str] | None = None
    ):
        self.id = id
        self.type = type
        self.roles = roles if roles is not None else []
        self.attributes = attributes if attributes is not None else {}

    def __repr__(self):
        return (
            f"Subject("
            f"id={self.id!r}, "
            f"type={self.type!r}, "
            f"roles={self.roles!r}, "
            f"attributes={self.attributes!r}"
            f")"
        )