# HIT-AND-RUN
This repository is a proof-of-concept for Hit-And-Run, a technique for executing syscalls using debug registers and the exception handler while maintaining a legitimate-looking call stack. The main purpose is to attempt to bypass both EDR's inline hooking and call stack analysis mechanisms.

![image](https://github.com/user-attachments/assets/28706f04-ac41-4ecd-b60d-b9a3cda57277)

To learn more about the technique, here is my blog post about it: [Hit-And-Run: A Novel Syscall Method](https://medium.com/bugbountywriteup/hit-and-run-a-novel-syscall-method-for-bypassing-edrs-via-veh-and-call-stack-theft-e2f399d71eeb)

## UPGRADES
With time, some improvements have been made to the original technique presented in the blog post:
- Use of the built-in exception handler instead of VEH (https://github.com/UmaRex01/Hit-And-Run/pull/1).
- Use thread variables instead of static variables to make the technique thread-safe.

## DEVELOPMENT
For those interested in experimenting with this technique on other APIs, the steps are as follows: 
- Add the API definition to Native.h
- Add the API wrapper definition to HitAndRun.h
- Implement the wrapper in HitAndRun.c, building on the existing wrappers. A wrapper is nothing more than a function that prepares the execution context, sets debug registers, and then calls the API.
