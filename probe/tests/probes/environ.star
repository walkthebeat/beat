"""environ(): names, values of known-safe names with passwords masked, and for the rest a token, never the value."""
def main() -> None:
    for v in environ(42):
        emit("env:" + v.name, "value", v.value if v.value != None else v.hash, "environ")
        emit("env:" + v.name, "hidden", str(v.value == None), "environ")
    def gone():
        return environ(43)
    each([1], lambda _: gone())
