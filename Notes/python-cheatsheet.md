---
title: "Python Developer Cheatsheet"
slug: "python-cheatsheet"
created: "2026-04-25"
ingested_at: "2026-04-25T00:00:00Z"
summary: "Essential Python syntax, idioms, and patterns for daily development"
tags: [python, programming, cheatsheet, languages]
category: development
difficulty: beginner
key_concepts: [syntax, decorators, context-managers, type-hints, asyncio]
questions_answered: [how-to-use-f-strings, how-to-handle-exceptions, how-to-async-await]
provider: manual
status: active
type: reference
---

# Python Developer Cheatsheet

## Quick Syntax

### Variables & Types
```python
x: int = 42
y: str = "hello"
z: list[int] = [1, 2, 3]
d: dict[str, int] = {"a": 1}
```

### F-Strings (Python 3.6+)
```python
name = "World"
print(f"Hello, {name}!")
value = 42
print(f"Value: {value:05d}")  # Formatted output
```

### List/Dict Comprehension
```python
squares = [x**2 for x in range(10)]
even_squares = {x: x**2 for x in range(10) if x % 2 == 0}
```

## Decorators
```python
def timer(func):
    def wrapper(*args, **kwargs):
        import time
        start = time.time()
        result = func(*args, **kwargs)
        print(f"Took {time.time() - start:.3f}s")
        return result
    return wrapper

@timer
def slow_function():
    import time
    time.sleep(1)
```

## Context Managers
```python
with open("file.txt") as f:
    content = f.read()  # Auto-closes

from contextlib import contextmanager

@contextmanager
def my_context():
    print("Enter")
    yield
    print("Exit")

with my_context():
    print("Inside")
```

## Async/Await (Python 3.7+)
```python
import asyncio

async def fetch(url):
    # Pretend HTTP call
    await asyncio.sleep(1)
    return f"Data from {url}"

async def main():
    results = await asyncio.gather(
        fetch("api1.com"),
        fetch("api2.com")
    )
    return results

asyncio.run(main())
```

## Common Patterns

### Try/Except
```python
try:
    x = int("not a number")
except ValueError as e:
    print(f"Error: {e}")
else:
    print("Success!")
finally:
    print("Cleanup")
```

### Testing with unittest
```python
import unittest

class TestMath(unittest.TestCase):
    def test_addition(self):
        self.assertEqual(2 + 2, 4)

if __name__ == "__main__":
    unittest.main()
```

## Useful Built-ins
- `enumerate()` - loop with index
- `zip()` - pair up iterables
- `map()`, `filter()` - functional style
- `isinstance()`, `hasattr()` - introspection
- `dir()` - list attributes

## Resources
- [Python Docs](https://docs.python.org)
- [Real Python](https://realpython.com)
- [Python Enhancement Proposals](https://peps.python.org)
