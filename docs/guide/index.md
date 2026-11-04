# Why beat

**Alpha: we are still developing, and we invite you to try it.** The functionality works. The site is not highly
available: one server, with daily snapshots within one AWS account and no outside monitoring yet. If that server is lost, you could lose up to a day of survey history and enrolment. Commands and the sensor's protocol may still change.

Everyone wants an agent on their production now, including the people who built the system. Today there are two ways
to get one there. You can give it the logs, which are not enough: logs hold only what someone thought to log. Or you
can give it your own production credentials, which works and is not safe, and engineers do it anyway, because they
need the help.

beat is the third way. Your agent reads your Linux hosts as deep as root can, across the whole fleet at once, without your production credentials, and with no way to run anything but read-only questions.

Then comes the part that is hard to explain until you see it. You say "see what you can figure out", and it comes back
with things you never thought to ask about. Pointed at our own production, it ran into a 12-hour outage of our API
that no alert had reported, and traced the cause. It also pointed out that our certificate reload had never run, with
its first renewal weeks away, and that the next reboot would be that configuration's first cold boot.

I have used this, and I miss it at work. I know now that it is possible, and there I do not have it.

## What happened when we asked

**You support a 1000-node Slurm cluster and nodes keep going down. Which of the thousands of jobs is doing it?** In a
simulated cluster that size, the agent was told only that nodes were being marked down. About 5 minutes later it had
tied all 47 nodes failing a health check to one user's new build, and set aside the nodes that were failing for other
reasons.

**Three of your sixteen nodes run every job from `/tmp`, and nobody has noticed. Why?** Nobody asked this: a plain
discovery of a new cluster flagged it. One follow-up question and 14 minutes later, it named a race in our own
provisioning: those nodes looked up a home directory just before it was created, and the kernel's NFS client cached
the miss and never checked again. We had not planted that. We did not know it was there.

**The queue is stuck and the node is idle. What is holding it?** Also not planted. Stopping our lab mid-job left Slurm
reloading a dead job as running, holding every CPU. The agent read the controller's log and saved state, said which
part was inference, and confirmed it. When the job was cancelled, the next one started 19 seconds later.

**A job has slowed down and all sixteen nodes look equally busy. Which ones are the cause?** In a coupled job, everyone
waits for the slowest, so every host looks the same. With faults we injected, the agent named the exact 4 nodes out of
16, and told their two different causes apart.

**A job hangs and the hosts look fine. How far down does it go?** We paused the cloud volume under a cluster's NFS
homes. In 7.5 minutes the agent traced the hang to the stalled device and stopped at "trigger: external, not
identified", with the evidence to check next, where it could have made up a story.

**A certificate is about to expire and nothing will renew it. Would you know?** On a web server in our lab, nobody
asked about certificates. Discovery reported one six days from expiry with nothing to renew it, and a scheduler agent
logging "heartbeat ok" without ever contacting its server. We planted those two, to see whether it would look.

**You just deployed. Is it actually running?** We edited a live nginx configuration, `nginx -t` passed, and nobody
reloaded it. Asked what had changed, the agent compared the file's time with the process's start and said the change
was probably not in effect. On our own production, we wrote down what had to be true for a fix to hold, and checked
each item with beat when the moment came. It held through its first test.

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
- **Deploys** are the least tested. Your agent compares when you ask. There is no automatic pass or fail for a rollout
  yet, and we have not run a staged rollout as a test.
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
