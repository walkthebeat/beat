# Why beat

Everyone wants an agent on their production now, including the people who built the system. Today there are two ways
to get one there. You can give it the logs, which are not enough: logs hold only what someone thought to log. Or you
can give it your own production credentials, which works and is not safe, and engineers do it anyway, because they
need the help.

beat is the third way. Your agent reads your Linux hosts as deep as root can, across the whole fleet at once, without your production credentials, and with no way to run anything but read-only questions.

Then comes the part that is hard to explain until you see it. You say "see what you can figure out", and it comes back
with things you never thought to ask about. On our own production, it found that our certificate reload had never
run, with its first renewal weeks away, and that the next reboot would be that configuration's first cold boot.

## What happened when we asked

We run beat against scenarios in our labs and on our own hosts: faults we injected, and some we did not know were
there. In a simulated 1000-node Slurm cluster, it tied 47 failing nodes to one user's new build in about 5 minutes. A
plain discovery of a fresh 16-node cluster found three nodes running every job from `/tmp`, and traced it to a race
in our own provisioning that nobody had planted. When a job hung on hosts that looked fine, it followed the hang down
to a paused cloud volume, and said the trigger was not identified rather than make one up.

## What it is

- **A sensor** on each Linux host, which runs the questions you send and returns the answers.
- **The beat service**, which keeps each org's questions and answers apart from every other org's.
- **The `beat` CLI and your agent** (Claude Code, today) on your laptop, which ask the questions and read the answers.
- **An estate repository**, yours, in git: what is known about your hosts, the probes, your notes, past incidents.
  It keeps what the agent learned for the next session, and the next person.

beat is not an agent: you bring your own. It does not fix anything: every change to a host stays yours to make.

Answers go from your sensors to walkthebeat's store, where walkthebeat can read them, and from there to your laptop
and the model provider your agent uses.

## What you can hold it to

- **Read-only.** Questions run with a read-only view of the host, no network and limits on time and memory.
- **Plain about privilege.** The sensor runs as root, so that it can read what an administrator can. It listens on no
  port and connects out.
- **It obeys your org.** It runs only questions signed by a member of your org. Neither the service nor walkthebeat
  can make it run anything on their own.
- **Sources and silence.** Answers say where they came from, and a host that did not answer is reported as such, not
  left out.
- **Secrets, as far as it can.** Secret files are replaced by placeholders and known kinds of secret are masked. That
  will not catch every secret.

## How far this has been tested

- **Scale.** The largest real cluster so far has 16 nodes. The 1000-node result is one run, in simulation. No real
  grid of that size has run beat, and the hosted service has not carried that load.
- **Evidence.** All of it comes from our labs and our own hosts, and most of the faults were ours. There is no outside
  production record yet.
- **It can be wrong.** One run invented a trigger, one missed a live setting with confidence, and earlier runs needed
  a nudge to get past the symptom. Read its evidence as you would a colleague's.
- **It answers when asked.** It does not watch your hosts or alert between sessions yet.

## Tell us what is wrong

We want to hear what broke, what confused you, and what your agent could not see. [Open an issue or start a discussion](https://github.com/walkthebeat/feedback). A report you choose to send with `beat report` may include your hostnames and configuration, and walkthebeat reads it.

## Next

- [Getting started](getting-started.md): from sign-up to a first question, on one host or many.
- [The sensor](sensor.md): what it does on a host, what it sends, and how to remove it.
