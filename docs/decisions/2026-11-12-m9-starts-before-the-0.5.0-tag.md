# M9 starts before the 0.5.0 tag

*Decided 2026-11-12 by the supervisor; the owner can overrule.*

The M9 brief says M9 "starts after Zigbox 0.5.0 is tagged". That was the supervisor's choice, made
so that M9's work would not land in the release. 0.5.0 is cut from its own branch
(`claude/release-0.5.0`, PR #107), whose code is frozen and reviewed, so M9 work on `main` cannot
reach it. Minimizing the time to release (`2026-11-11-minimize-time-to-release.md`) favours
starting now.

So M9 slice 1 starts on 2026-11-12, before the tag. The rest of the brief stands. If a fix has to go
into 0.5.0 after M9 work has landed on `main`, it goes on the release branch alone.

M10 is not changed: "starts after 0.5.0" is in the owner's decision
(`2026-11-11-m10-gpu-decisions.md`), and only the owner can move it.
