# HIT-AND-RUN
Hit-And-Run is a proof-of-concept implementation of a syscall technique for evading EDRs systems using a novel combination of call stack theft and vectored exception handling (VEH). This technique executes syscalls with attacker-defined parameters while maintaining a legitimate-looking call stack, effectively evading both inline hooking and call stack analysis mechanisms.

![image](https://github.com/user-attachments/assets/28706f04-ac41-4ecd-b60d-b9a3cda57277)

## Key Features
- **Call Stack Theft**: Mimics standard Windows API behavior to create a coherent call stack, avoiding detection.
- <s>Vectored Exception Handling (VEH): Dynamically handles exceptions to manipulate syscall execution flow.</s>
  - **[PATCH 1] Built-In Exception Handling**: Dynamically handles exceptions to manipulate syscall execution flow.
- **Hardware Breakpoints**: Utilized to intercept and redirect execution without modifying code, reducing detection risk.
  
## Limitations
- <s>The setup phase (e.g., AddVectoredExceptionHandler) and</s> the use of debug registers (e.g., Dr0, Dr7) may trigger EDR alerts.
  - Patch 1 replaced VEH with built-in exception handling, effectively removing the IOC associated with the use of API `AddVectoredExceptionHandler`.
- Repeated exceptions and predictable behavior patterns could be flagged by behavior-based detection systems.
  
## Learn More
For detailed implementation steps and technical insights, refer to the blog post: [Hit-And-Run: A Novel Syscall Method](https://medium.com/bugbountywriteup/hit-and-run-a-novel-syscall-method-for-bypassing-edrs-via-veh-and-call-stack-theft-e2f399d71eeb)
