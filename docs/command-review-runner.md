# Command review runners

A command runner lets you plug your own model CLI or wrapper into hangover. The
runner is a trusted subprocess, not a hangover sandbox: it can read and execute
whatever its account can. Review only repositories and source boundaries you
have approved, and supply read-only enforcement in the wrapper if you need it.

## Generic contract

Merge this review block into the target repository's `.hangover/config.json`,
replacing the executable with your own wrapper:

```json
{
  "review": {
    "runner": "command",
    "timeout_seconds": 1200,
    "command": [
      "/absolute/path/to/review-wrapper",
      "{prompt}", "{output}", "{schema}", "{repo}"
    ],
    "env": []
  }
}
```

The command is an argv template, never a shell string. Placeholders must be whole
arguments:

- `{prompt}` is the prompt file. If omitted, the prompt arrives on stdin.
- `{output}` is where the runner must write its review JSON. If omitted, hangover
  parses stdout as review JSON.
- `{schema}` is the JSON Schema file the review must satisfy.
- `{repo}` is the repository directory; it is also the subprocess's working directory.

The runner must return a complete JSON review matching the schema and requested
mode, including the verification token for a post-fix review. Exit nonzero on
transport, authentication, truncation, or extraction failure; never turn those
into an empty successful review. Hangover validates the result independently.
New configs start with an empty `review.env`. Add only environment variable
names your runner needs; their values come from the invoking environment and
belong outside this tool's repository.

## Example: Claude through delegate

[examples/review-claude.sh](examples/review-claude.sh) is one optional wrapper. It
requires Bash, Python 3, and an authenticated `delegate` CLI on PATH. Delegate is
an operator-installed tool that routes prompts to model back ends; it is not
included with agent-hangover. Substitute your own CLI using the contract above
if you do not use delegate.

Run the example from where hangover is installed, not a detached copy: it reuses
hangover's parser from the `src/` beside it. In a clone its path is
`docs/examples/review-claude.sh`; npm ships it at
`$(npm root -g)/agent-hangover/docs/examples/review-claude.sh`. Set `review.command`
to:

```json
[
  "bash",
  "/absolute/path/to/agent-hangover/docs/examples/review-claude.sh",
  "{prompt}", "{output}", "{schema}", "{repo}"
]
```

Its model and reasoning settings are explicit in the script. It requests
`claude safe`; enforcement belongs to the installed delegate/Claude adapter.
The wrapper embeds the schema in the prompt, rejects process failure, missing
or nonzero child exit status, explicit truncation, and unfinished JSON, and uses
the final complete review rather than a planning object. Hangover then validates
the requested review mode. `tests/test_command_recipe.py` exercises the actual
shell wrapper through `run_command_review` with a fixture delegate; these tests
do not claim a live model review.

If you do not need a wrapper, the built-in adapter is simpler:

```bash
hangover review --runner delegate --lane claude
hangover verify --issue <id> --runner delegate --lane claude
```

It writes a run-local schema copy without the dialect URI that Claude rejects.
The canonical schema and other lanes keep their existing transport.
