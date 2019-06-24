import my_debugger

debugger = my_debugger.debugger()
pid = input("Enter the PID of the process to attach to: ")
debugger.attach(int(pid))
listing = debugger.enumerate_threads()

# for each thread in the list, grab the value of each registers
for thread in listing:
    thread_content = debugger.get_thread_context(thread)
    # output the contents of registers
    print("[*] Dumping registers for thread ID: 0x%08x" % thread)
    print("[] EIP: 0x%08x" % thread_context.Eip)
    print("[] ESP: 0x%08x" % thread_context.Esp)
    print("[] EBP: 0x%08x" % thread_context.Ebp)
    print("[] EAX: 0x%08x" % thread_context.Eax)
    print("[] EBX: 0x%08x" % thread_context.Ebx)
    print("[] ECX: 0x%08x" % thread_context.Ecx)
    print("[] EDX: 0x%08x" % thread_context.Edx)
    print("[] END DUMP")

debugger.detach()
