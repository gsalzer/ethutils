# `parse_hex`: Decode hexadecimal bytecode

## Interface

```python
parse_hex(text: str) -> bytes
```

Import it from the package's public API:

```python
from ethutils import parse_hex
```

## Arguments

`text`
: A hexadecimal string. It may begin with `0x` or `\x`, with either letter in
  upper or lower case. ASCII whitespace between byte pairs is allowed.

  The argument must be a `str`. Pass bytecode that is already represented as
  `bytes` directly to the other API functions instead of converting it with
  `parse_hex`.

## Return value

A `bytes` object containing the decoded byte values.

`parse_hex` raises `TypeError` when `text` is not a string. It raises
`ValueError` when the text contains non-hexadecimal characters or an incomplete
byte. An optional prefix is removed before decoding and is not part of the
result.

## Description

Most `ethutils` functions accept bytecode as `bytes`, not as a hexadecimal
string. `parse_hex` is the explicit conversion step for bytecode copied from
compiler output, RPC responses, block explorers, or text files.

After removing surrounding whitespace and one optional prefix, decoding follows
Python's `bytes.fromhex` rules. In particular, whitespace may separate complete
bytes, but it cannot split the two hexadecimal digits belonging to one byte.
The function does not validate whether the result is executable EVM bytecode;
every byte sequence has a valid hexadecimal representation.

## Examples

### Decode prefixed bytecode

```python
from ethutils import parse_hex

code = parse_hex("0x6001600055")

print(code)
# b'\x60\x01\x60\x00\x55'

print(code.hex())
# 6001600055
```

The input string contains ten hexadecimal digits, or five byte values. The
result therefore has length five:

```python
len(code)
# 5
```

### Decode formatted input

Whitespace can make longer bytecode easier to read:

```python
code = parse_hex("""
    60 01
    60 00
    55
""")

code == bytes([0x60, 0x01, 0x60, 0x00, 0x55])
# True
```

A literal `\x` prefix is also accepted:

```python
parse_hex(r"\x6000")
# b'\x60\x00'
```

### Invalid input

Each byte requires exactly two hexadecimal digits:

```python
parse_hex("0x600")
# Raises ValueError because the final byte is incomplete.
```

Text placeholders are not resolved:

```python
parse_hex("60__$abcd$__00")
# Raises ValueError because the placeholder is not hexadecimal.
```
