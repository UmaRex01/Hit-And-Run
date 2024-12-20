# HIT-AND-RUN
Hit-And-Run is a proof-of-concept implementation of a syscall technique for evading EDRs systems using a novel combination of call stack theft and vectored exception handling (VEH). This technique executes syscalls with attacker-defined parameters while maintaining a legitimate-looking call stack, effectively evading both inline hooking and call stack analysis mechanisms.

![image](https://github.com/user-attachments/assets/28706f04-ac41-4ecd-b60d-b9a3cda57277)

## Key Features
- **Call Stack Theft**: Mimics standard Windows API behavior to create a coherent call stack, avoiding detection.
- **Vectored Exception Handling (VEH)**: Dynamically handles exceptions to manipulate syscall execution flow.
- **Hardware Breakpoints**: Utilized to intercept and redirect execution without modifying code, reducing detection risk.
  
## Limitations
- The setup phase (e.g., AddVectoredExceptionHandler) and the use of debug registers (e.g., Dr0, Dr7) may trigger EDR alerts.
- Repeated exceptions and predictable behavior patterns could be flagged by behavior-based detection systems.
  
## Learn More
For detailed implementation steps and technical insights, refer to the blog post: *coming soon*
