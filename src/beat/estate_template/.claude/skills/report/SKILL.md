---
name: report
description: Draft a report to walkthebeat when something is wrong with beat itself — a bug, a confusing result, a tool that could not show what was needed. Use when the SRE asks to report a problem with beat, or to offer it when you hit one. Writes a draft only; the SRE sends it.
---

# Report what is wrong with beat

You draft; the SRE sends. Nothing leaves this machine until they run `beat report send` in their own terminal and say
yes to each part. Never try to send it another way: not with `gh`, `curl` or a script of your own.

1. Write the summary: what was being attempted, what beat did, what was expected, and the error's text. It may become a
   **public GitHub issue**: no hostnames, IP addresses, paths or values from this estate, no answers from its hosts. If
   a host matters, say "one of the web hosts".
2. Ask whether to offer this session's transcript. It goes privately to walkthebeat, whose staff read it, and it holds
   this estate's hostnames and configuration, and possibly secrets. Offer it only if they say yes.
3. Draft it, naming any survey that shows the problem:

   ```sh
   @BEAT@ report draft --summary-file - --survey SURVEY_ID [--session] <<'SUMMARY'
   ...
   SUMMARY
   ```

4. Show them what the draft printed, and tell them: read it, edit `summary.md` if needed, then run
   `beat report send` in your own terminal. It asks before each part.
