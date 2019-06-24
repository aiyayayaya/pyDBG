from ctypes import *
from my_debugger_defines import *


kernal32 = windll.kernel32

class debugger():
    def __init__(self):
        pass

    def open_thread(self, thread_id):
        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)
        if h_thread is not None:
            return h_thread
        else:
            print("[g] Could not obtain a valid thread handle.")

    def enumerate_threads(self):
        thread_entry = THREADENTRY32()
        thread_list = []
        sapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid)
        if snapshot is not None:
            #set the size of the struct or the call fail
            thread_entry.dwSize = sizeof(thread_entry)
            success = kernel32.Thread32First(snapshot, byref(thread_entry))
        while success:
            if thread_entry.th32OwnerProcessID == self.pid:
                thread_list.append(thread_entry.th32ThreadID)
                success =h kernel32.Thread32Next(snapshot, byref(thread_entry)
                        kernel32.CloseHandle(snapshot)
                        return thread_list
        else:
        return False

    def get_thread_context(self, thread_id):
        context = CONTEXT()
        cnotext.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS

        # Obtain a handle to the thread
        h_thread = self.open.thread(thread_id)
        if kernel32.GetThreadContext(h_thread, byref(context)):
            kernel32.CloseHandle(h_thread)
        else:
            return False

    def load(self, path_to_exe):

        # dwCreation flag determines how to create the process
        # set creation_flags = CREATE_NEW_CONSOLE if you want to see the calculator GUI
    
        creation_flags = DEBUG_PROCESS

        # instantiate the structs
        startupinfo = STARTUPINFO()
        process_information = PROCESS_INFORMATION()

        # the following options allow the started process to be shown as a separate window
        # it also illustrates how different settings in the STARTUPINFO struct can affect the debugger
        startupinfo.dwFlags = 0x1
        startupinfo.wShowWindow = 0x0

        # then initialize the cb variable in the STARTUPINFO struct, just the size of the struct itself
        startupinfo.cb = sizeof(startupinfo)

        if kernel32.CreateProcessA(
                path_to_exe,
                None,
                None,
                None,
                None,
                creation_flags,
                None,
                None,
                byref(startupinfo),
                byref(process_information)):
            print("[*] We have successfully launched the process!")
            print("[*] PID: %d" % process_information.dwProcessId)
        else:
            print("[*] Error: 0x%08x." % kernel32.GetLastError())

