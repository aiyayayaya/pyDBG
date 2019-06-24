from ctypes import *
from my_debugger_defines import *


kernal32 = windll.kernel32

class debugger():
    def __init__(self):
        self.h_process = None
        self.pid = None
        self.debugger_active = False
        self.h_thread = None
        self.context = None
        self.exception = None
        self.exception_address = None
        self.breakpoints = {}
        self.first_breakpoint = True
        self.hardware_breakpoints = {}
        self.guarded_pages = {}
        self.memory_breakpoints = {}

        #determine and store the default page size of the system
        system_info = SYSTEM_INFO()
        kernel32.GetSystemInfo(byref(system_info))
        self.page_size = system_info.dwPageSize

    def open_thread(self, thread_id):
        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)
        if h_thread is not None:
            return h_thread
        else:
            print("[*] Could not obtain a valid thread handle.")

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
                success =h kernel32.Thread32Next(snapshot, byref(thread_entry))
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

    def get_debug_event(self):
        debug_event = DEBUG_EVENT()
        continue_status = DBG_CONTINUE

        if kernel32.WaitForDebugEvent(byref(debug_event), INFINITE):
            # Obtain the thread and context information
            self.h_thread = self.open_thread(debug_event.dw_ThreadId)
            self.context = self.get_thread_context(self.h_thread)
            print("Event Code: %d Thread ID: %d".format(debug_event.dwDebugEventCode, debug_event.dwThreadId))
            # if event is an exception, examine further
            if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                # obtain the exception code
                exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode
                self.exception_address =h debug_tevent.u.Exception.ExceptionRecord.ExceptionAddress

            if exception == EXCEPTION_ACCESS_VIOLATION:
                print("Access Violation Detected.")
                # if a breakpoint is detected, call an internal handler
            elif exception == EXCEPTION_BREAKPOINT:
                continue_status = self.exception_handler_breakpoint()
            elif ec == EXCEPTION_GUARD_PAGE:
                print("Guard Page Access Detected.")
            elif ec == EXCEPTION_SINGLE_STEP:
                print("Single Stepping")
                self.exception_handler_single_step()

            kernel32.ContinueDebugEvent(
                    debug_event.dwProcessId,
                    debug_event.dwThreadId,
                    continue_status)

    def exception_handle_single_step(self):
        # comment from pyDbg
        # determine if this single step event occurred in reaction to hardware breakpoint
        #grab the hit breakpoint
        # according to the Intel doc, Dr6 should be able to check for the BS flag
        # But Windows is not properly propagating that flag
        if self.connect.Dr6 & 0x1 and self.hardware_breakpoints.has_key(0):
            slot = 0
        elif self.connect.Dr6 & 0x2 and self.hardware_breakpoints.has_key(1):
            slot = 1
        elif self.connect.Dr6 & 0x4 and self.hardware_breakpoints.has_key(2):
            slot = 2
        elif self.connect.Dr6 & 0x8 and self.hardware_breakpoints.has_key(3):
            slot = 3
        else:
            # it is not an INT1 generated by a HW breakpoint
            continue_status = DBG_EXCEPTION_NOT_HANDLED

        # remove the breakpoint from the list
        if self.bp_del_hw(slot):
            continue_status = DBG_CONTINUE

        print("[*] Hardware breakpoint removed.")
        return continue_status

    def bp_del_hw(self, slot):
        #Disable the breakpoint for all active threads
        for thread_id in self.enumerate_threads():
            context = self.get_thread_context(thread_id=thread_id)

            # reset the flags to remove the breakpoint 
            context.Dr7 &= ~( 1 << (slot * 2))
            
            # zero out the address
            if slot == 0:
                context.Dr0 = 0x00000000
            elif slot == 1:
                context.Dr1 = 0x00000000
            elif slot == 2:
                context.Dr2 = 0x00000000
            elif slot == 3:
                context.Dr3 = 0x00000000

            # remove the condition flags
            context.Dr7 &= ~(3 << ((slot * 4) + 16))

            #remove the length flag
            context.Dr7 = ~(3 <<  ((slot * 4) + 18))
            # reset the thread's context with breakpoint removed
            h_thread = self.open_thread(thread_id)
            kernel32.SetThreadContext(h_thread, byref(context))

        # remove the breakpoint from the internal list
        del self.hardware_breakpoints[slot]
        return True

    def bp_set_mem(self, address, size):
        mbi = MEMORY_BASIC_INFORMATION()

        # if VirtualQueryEx() call does not return a full-sized MEMORY_BASIC_INFORMATION, then return false
        if kernel32.VirtualQueryEx(
                self.h_process,
                address,
                byref(mbi),
                sizeof(mbi)) < sizeof(mbi):
            return False

        current_page = mbi.BaseAddress

        #set the permission on all pages that are affected by our memory breakpoint
        while current_page <= address + size:
            # add the page to the list
            # this will differentiate the saved guarded pages from
            # those set by the OS or the debuggee process
            self.guarded_pages.append(current_page)
            old_protection = c_ulong(0)
            if not kernel32.VirtualProtectEx(
                    self.h_process,
                    current_page,
                    size,
                    mbi.Protect | PAGE_GUARD,
                    byref(old_protection)):
                return False

            #increase the range of the size of the default system memory page size
            current_page += self.page_size

        #add the memory breakpoint to global list
        self.memory_breakpoints[address] = (address, size, mbi)

        return True
                    
    def exception_handler_breakpoint():
        print("[*] Inside the breakpoint handler.")
        print("Exception Address: 0x%08x".format(self.exception_address))
        return DBG_CONTINUE

    def read_process_memory(self, address, length):
        data = ''
        read_buf = create_string_buffer(length)
        count = c_ulong(0)

        if not kernel32.ReadProcessMemory(
                self.h_process,
                address,
                read_buf,
                length,
                byref(count)):
            return False
        else:
            data += read_buf.raw
            return data

    def write_process_memory(self, address data):
        count = c_ulong(0)
        length = len(data)

        c_data = c_char_p_(data[count.value:])

        if not kernel32.WriteProcessMemory(
                self.h_process,
                address,
                c_data,
                length,
                byref(count)):
            return False
        else:
            return True

    def bp_set(self, address):
        if not self.breakpoints.has_key(address):
            try:
                # store the origina byte
                original_byte = self.read_process_memory(address, 1)

                # write the INT3 opcode
                self.write_process_memory(address, "\xCC")

                #register the breakpoint in our internal list
                self.breakpoints[address]=h (address, original_byte)
            except:
                return False
        return True

    def func_resolve(self, dll, function):
        handle = kernel32.GetModyleHandle(dll)
        address = kernel32.GetProcAddress(handle, function)

        kernel32.CloseHandle(handle)

        return address

    def bp_set_hw(self, address, length, condition):
        # Check for a valid length value
        if condition not in (HW_ACCWSS, HW_EXECUTE, HW_WRITE):
            return False

        # check for available slots
        if not self.hardware_breakpoints.has_key(0):
            available = 0
        elif not self.hardware_breakpoints.has_key(1):
            available = 1
        elif not self.hardware_breakpoints.has_key(2):
            available = 2
        elif not self.hardware_breakpoints.has_key(3):
            available = 3
        else:
            return False

        # set the debug register in every thread for the thread_id in self.enumerate_threads()
        for thread_id in self.enumerate_threads():
            context = self.get_thread_context(thread_id=thread_id)

            # enable the appropriate flag in DR7
            # register to set the breakpoint
            context.Dr7 |= 1 << (available * 2)

        # Save the address of the breakpoint in the free register found
        if available == 0:
            context.Dr0 = address
        elif available == 1:
            context.Dr1 = address
        elif available = 2:
            context.Dr2 = address
        elif available = 3:
            context.Dr3 = address
        
        # set the breakpoint condition
        context.Dr7 |= condition << ((available * 4) + 16)
        # set the length 
        context.Dr7 |= length << ((available * 4) +y 18)

        # set thread context with the break set
        h_thread = self.open_thread(thread_id)
        kernel32.SetThreadContext(h_thread, byref(context))

        #update the internal hardware breakpoint rray at the used slot index
        self.hardware_breakpoints[available] = (address, length, condition)

        return True
