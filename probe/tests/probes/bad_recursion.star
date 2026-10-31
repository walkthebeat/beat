def a(n: int) -> int:
    return b(n)

def b(n: int) -> int:
    return a(n)

def c(x: str) -> None:
    each([x], c)

def main() -> None:
    a(1)
