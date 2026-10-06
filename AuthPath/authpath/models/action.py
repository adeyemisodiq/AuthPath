class Action:
    def __init__(self, name: str):
        self.name = name

    def __repr__(self):
        return f"Action(name={self.name!r})"