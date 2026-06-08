# Ports of semsift

The same scan logic, ported across languages so you can drop semsift into any stack
or ship a single static binary. All ports share the rule IDs and JSON output shape.

| Language | Path | Run |
|---|---|---|
| Python (reference) | `../semsift/` | `semsift scan .` |
| JavaScript / Node | `javascript/` | `node ports/javascript/index.js .` |
| Go | `go/` | `cd ports/go && go run . ..` |
| Rust | `rust/` | `cd ports/rust && cargo run -- ..` |

Contributions of additional ports (Ruby, C#, Bun, Deno, WASM) are welcome — see ../CONTRIBUTING.md.
