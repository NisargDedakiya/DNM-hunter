# Deep Binary Analysis (`deep_binary`)

The heaviest tier of native analysis: **symbolic execution** of a compiled
binary with [angr](https://angr.io). Where `binary_audit` statically reports
*missing protections*, this actually reasons about program state to **find and
prove bugs**.

## Capabilities

### `reach_target(binary, target)`
Solves for a concrete input (stdin) that drives execution to a target address or
symbol — a hidden `authenticated()`/`win()` function or a dangerous call. It does
not just say "there is a check"; it produces the input that passes it.

```
reach_target("./license", "authenticated")
#  -> reached=True, stdin=b"S3CR3T"     (angr solved the branch conditions)
```

### `find_control_hijack(binary)`
Feeds symbolic input and detects an **unconstrained state** — the instruction
pointer becomes attacker-controlled. That is the signature of an exploitable
memory-corruption bug (stack overflow via `gets`/`strcpy`), with the input
length that triggers it.

```
find_control_hijack("./overflow")
#  -> hijackable=True, overflowLen=254   ("symbolic PC — input controls RIP")
```

## Usage

```bash
pip install angr                       # optional, heavy — see requirements.txt
python -m deep_binary ./bin --reach authenticated
python -m deep_binary ./bin --hijack --json
```

Every run is bounded by a wall-clock budget and a step cap, so path explosion
can't hang the caller. angr is optional: the module imports without it and
reports `HAVE_ANGR`; the plugin is marked `community` for that reason.

## Where this sits

- `binary_audit` = fast, deterministic first pass (checksec + dangerous imports).
- `deep_binary` = slow, thorough second pass (symbolic execution) run on the
  handful of binaries the first pass flags as interesting.

Full interactive decompilation (Ghidra/IDA) remains a manual, human-driven step;
this automates the parts that are automatable.

## Tests

```bash
python -m unittest deep_binary.tests.test_symbolic -v   # compiles targets, solves them; skips without angr/gcc
```
