[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/Velixxyz/makefun-github-core-clone-01/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/Velixxyz/makefun-github-core-clone-01/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

# Forge

A single-file GitHub-compatible git forge, written for the
`github-core-clone-01` competition. One Node process serves the whole
surface from its own in-memory store:

- git smart HTTP, protocol v2 and v0: advertisements, `ls-refs`, fetch
  (including shallow and deepen), and receive-pack with per-ref reports.
- the REST v3 endpoints the suite exercises: repositories, refs, branches,
  commits, contents, labels, issues, comments, pull requests and merges.
- a small GraphQL executor covering the fixed documents the suite sends,
  including cursor pagination, introspection and the five mutations.
- the MCP Streamable HTTP endpoint with the six repository tools.
- the make.fun lifecycle: register a port, answer health checks, wait for
  the suite to finish, then exit.

Only Node builtins are used. State is deterministic: every timestamp
derives from one fixed epoch plus a monotonic counter, so repeated trials
observe identical state.

Run it with:

```sh
node --experimental-strip-types main.ts
```

With `MAKEFUN_ENV_URL` and `MAKEFUN_SHOP_TOKEN` set, the process registers
with the suite environment and exits when the suite reports done. Without
them it serves on an ephemeral port and prints the port number.
