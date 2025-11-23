import ctypes
from ctypes import c_void_p, c_char_p, c_uint32, c_uint16, c_uint64, c_int
from ctypes import c_bool, POINTER, Structure, CFUNCTYPE, c_size_t, c_byte
from enum import IntEnum
import queue
import threading
import platform


class CONTEXT(Structure):
    _fields_ = [
        ("P1Home", c_uint64),
        ("P2Home", c_uint64),
        ("P3Home", c_uint64),
        ("P4Home", c_uint64),
        ("P5Home", c_uint64),
        ("P6Home", c_uint64),
        ("ContextFlags", c_uint32),
        ("MxCsr", c_uint32),
        ("SegCs", c_uint16),
        ("SegDs", c_uint16),
        ("SegEs", c_uint16),
        ("SegFs", c_uint16),
        ("SegGs", c_uint16),
        ("SegSs", c_uint16),
        ("EFlags", c_uint32),
        ("Dr0", c_uint64),
        ("Dr1", c_uint64),
        ("Dr2", c_uint64),
        ("Dr3", c_uint64),
        ("Dr6", c_uint64),
        ("Dr7", c_uint64),
        ("Rax", c_uint64),
        ("Rcx", c_uint64),
        ("Rdx", c_uint64),
        ("Rbx", c_uint64),
        ("Rsp", c_uint64),
        ("Rbp", c_uint64),
        ("Rsi", c_uint64),
        ("Rdi", c_uint64),
        ("R8", c_uint64),
        ("R9", c_uint64),
        ("R10", c_uint64),
        ("R11", c_uint64),
        ("R12", c_uint64),
        ("R13", c_uint64),
        ("R14", c_uint64),
        ("R15", c_uint64),
        ("Rip", c_uint64),
    ]


class CDisasmLine(Structure):
    _fields_ = [
        ("address", c_uint64),
        ("bytes", c_char_p),
        ("instructions", c_char_p),
        ("hasBreakpoint", c_bool)
        ]


class CDataLine(Structure):
    _fields_ = [
        ("address", c_uint64),
        ("bytes", c_void_p),
        ("bytesSize", c_size_t),
        ("ascii", c_char_p)
    ]


class CDataSection(Structure):
    _fields_ = [
        ("secName", c_char_p),
        ("data", POINTER(CDataLine)),
        ("dataCount", c_size_t)
    ]

class CStackLine(Structure):
    _fields_ = [
        ("address", c_uint64),
        ("value", c_uint64),
        ("label", c_char_p)
    ]


class CDebugEvent(Structure):
    _fields_ = [
        ("type", c_int),
        ("address", c_uint64),
        ("message", c_char_p),
        ("disasmCode", POINTER(CDisasmLine)),
        ("disasmCodeCount", c_size_t),
        ("data", POINTER(CDataSection)),
        ("dataCount", c_size_t),
        ("stackData", POINTER(CStackLine)),
        ("stackDataCount", c_size_t),
        ("context", CONTEXT),
        ("startTrace", c_uint64),
        ("endTrace", c_uint64),
        ("prog", c_char_p)
    ]


class CExportedSymbol(Structure):
    _fields_ = [
        ("name", c_char_p),
        ("address", c_uint64)
    ]

class CModule(Structure):
    _fields_ = [
        ("name", c_char_p),
        ("baseAddress", c_uint64),
        ("sizeOfSymbols", c_size_t),
        ("symbols", POINTER(CExportedSymbol))
    ]

class CActiveThread(Structure):
    _fields_ = [
        ("threadId", c_uint32),
        ("hThread", c_void_p),  # HANDLE = void*
        ("isRunning", c_bool)
    ]

class CDebugObserver(Structure):
    _fields_ = [
        ("userData", c_void_p),
        ("update", CFUNCTYPE(None, POINTER(CDebugEvent))),  # ← функция обратного вызова
        ("plugName", c_char_p)
    ]


class CDebugEventType(IntEnum):
    CAPI__StartDebbug = 0
    CAPI__BreakpointEvent = 1
    CAPI__BreakpointSetup = 2
    CAPI__HardBreakpointSetup = 3
    CAPI__ModuleLoad = 4
    CAPI__ProcessExit = 5
    CAPI__CreateThread = 6
    CAPI__ExitThread = 7
    CAPI__ModuleUnload = 8
    CAPI__DbgStr = 9
    CAPI__Dump = 10
    CAPI__Reg = 11
    CAPI__ModList = 12
    CAPI__ThreadList = 13
    CAPI__BreakList = 14
    CAPI__HwBreakList = 15
    CAPI__CreateProc = 16
    CAPI__DisasmCode = 17
    CAPI__HardwareBreak = 18
    CAPI__InputError = 19
    CAPI__Step = 20
    CAPI__Run = 21
    CAPI__DbgError = 22
    CAPI__DbgWarning = 23
    CAPI__StepOver = 24
    CAPI__StepOut = 25
    CAPI__Nope = 26
    CAPI__SetupTrace = 27
    CAPI__TraceStep = 28
    CAPI__LoadPlug = 29

class CBreakPoint(Structure):
    _fields_ = [
        ("address", c_uint64),
        ("saveByte", c_byte),
        ("temp", c_bool),
        ("enable", c_bool)
    ]

class CHwBreakPoint(Structure):
    _fields_ = [
        ("address", c_uint64),
        ("enable", c_bool),
        ("size", c_int),
    ]

class PlugCmd(Structure):
    _fields_ = [
        ("name", c_char_p),
        ("help", c_char_p),
        ("handler", CFUNCTYPE(c_char_p, c_char_p)),
        ("type", c_int)

    ]
dbg_set_bp_fn = CFUNCTYPE(c_bool, c_uint64)
dbg_del_bp_fn = CFUNCTYPE(None, c_uint64)
dbg_get_bp_list_fn = CFUNCTYPE(POINTER(CBreakPoint), POINTER(c_size_t))
dbg_set_hw_bp_fn = CFUNCTYPE(c_bool, c_uint64, c_char_p, c_size_t)
dbg_del_hw_bp_fn = CFUNCTYPE(c_bool, c_uint64)
dbg_get_hw_bp_list_fn =  CFUNCTYPE(POINTER(CHwBreakPoint), POINTER(c_size_t))
dbg_step_fn = CFUNCTYPE(None)
dbg_step_over_fn = CFUNCTYPE(None)
dbg_step_out_fn = CFUNCTYPE(None)
dbg_run_fn = CFUNCTYPE(None)
dbg_stop_fn = CFUNCTYPE(None)
dbg_get_context_fn = CFUNCTYPE(POINTER(CONTEXT))
dbg_change_reg_fn = CFUNCTYPE(c_bool, c_char_p, c_uint64)
dbg_mem_dump_fn = CFUNCTYPE(c_size_t, c_uint64, c_void_p, c_size_t)
dbg_mem_edit_fn = CFUNCTYPE(c_bool, c_uint64, c_void_p, c_size_t)
dbg_get_modules_fn =  CFUNCTYPE(POINTER(CModule), POINTER(c_size_t))
dbg_get_threads_fn = CFUNCTYPE(POINTER(CActiveThread), POINTER(c_size_t))
dbg_send_command_fn = CFUNCTYPE(None, c_char_p)
dbg_attach_fn = CFUNCTYPE(None, POINTER(CDebugObserver))
dbg_detach_fn = CFUNCTYPE(None, POINTER(CDebugObserver))
dbg_launch_fn = CFUNCTYPE(c_bool, c_char_p)
dbg_loop_fn = CFUNCTYPE(None)
dbg_free_bp_list = CFUNCTYPE(None, POINTER(CBreakPoint))
dbg_free_hw_bp_list = CFUNCTYPE(None, POINTER(CHwBreakPoint))
dbg_free_modules =  CFUNCTYPE(None, POINTER(CModule), c_size_t)
dbg_free_threads = CFUNCTYPE(None, POINTER(CActiveThread))
dbg_add_new_cmd = CFUNCTYPE(None, POINTER(PlugCmd))

class DebugCAPI(Structure):
    _fields_ = [
        ("setBP", dbg_set_bp_fn),
        ("delBP", dbg_del_bp_fn),
        ("getBpList", dbg_get_bp_list_fn),
        ("setHwBP", dbg_set_hw_bp_fn),
        ("delHwBP", dbg_del_hw_bp_fn),
        ("getHwBpList", dbg_get_hw_bp_list_fn),
        ("step", dbg_step_fn),
        ("stepOver", dbg_step_over_fn),
        ("stepOut", dbg_step_out_fn),
        ("run", dbg_run_fn),
        ("stop", dbg_stop_fn),
        ("getCont", dbg_get_context_fn),
        ("chgReg", dbg_change_reg_fn),
        ("memDump", dbg_mem_dump_fn),
        ("memEdit", dbg_mem_edit_fn),
        ("getMods", dbg_get_modules_fn),
        ("getThreads", dbg_get_threads_fn),
        ("sendCommand", dbg_send_command_fn),
        ("attach", dbg_attach_fn),
        ("detach", dbg_detach_fn),
        ("launchProg", dbg_launch_fn),
        ("dbgLoop", dbg_loop_fn),
        ("freeBpList", dbg_free_bp_list),
        ("freeHwBpList", dbg_free_hw_bp_list),
        ("freeModules", dbg_free_modules),
        ("freeThreads", dbg_free_threads),
        ("addNewCommand", dbg_add_new_cmd)
    ]




class AnnaDBG:

    def __init__(self, arch="x64"):

        if platform.architecture()[0] == '64bit':
            self.dll = ctypes.CDLL("G:\\dbg\\DebugCorex64.dll")
        else:
            self.dll=ctypes.CDLL("G:\\dbg\\DebugCorex86.dll")

        

        createFunc = self.dll.createDebugger
        createFunc.restype = c_void_p
        createFunc.argtypes = []
        self.debuggerPtr = createFunc()

        if not self.debuggerPtr:
            raise RuntimeError("Failed to create debugger instance")

        # Инициализируем DebugAPI
        initFunc = self.dll.initDebugAPI
        initFunc.argtypes = [c_void_p]
        initFunc(self.debuggerPtr) # ← теперь debug != nullptr

        getApi = self.dll.get_debug_api
        getApi.restype = POINTER(DebugCAPI)
        getApi.argtypes = []

        self.ptrApi = getApi()

        if not self.ptrApi:
            raise RuntimeError("Failed to get DebugCAPI")

        self.api = self.ptrApi.contents

        self.eventQueue = queue.Queue()
        self.eventCallback = None

        self._observers = {}


    def setBreakPoint(self, addr):
        return self.api.setBP(addr)

    def delBreakPoint(self, addr):
         self.api.delBP(addr)

    def step(self):
        self.api.step()

    def stepOver(self):
        self.api.stepOver()

    def stepOut(self):
        self.api.stepOut()

    def run(self):
        self.api.run()

    def stop(self):
        self.api.stop()


    def getContext(self):
        return self.api.getCont()

    def changeReg(self, reg: str, value: int) -> bool:
        return bool(self.api.chgReg(reg.encode('utf-8'), value))

    def dumpMem(self, addr: int, size: int):
        buf = (ctypes.c_ubyte * size)()
        actualSize = self.api.memDump(addr, buf, size)
        return bytes(buf[:actualSize])

    def editMem(self, addr: int, data: bytes) -> bool:
        buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        return bool(self.api.memEdit(addr, buf, len(data)))
    
    def launchProcess(self, exePath: str) -> bool:
        if not exePath:
            raise ValueError("exePath cannot be empty")

        encoded = exePath.encode('utf-8')
        if not encoded:
            raise ValueError("Failed to encode exePath")

        try:
            result = self.api.launchProg(encoded)
            return bool(result)
        except Exception as e:
            print(f"Error calling launch: {e}")
            return False

    def startEventloop(self):
        thread = threading.Thread(target=self.EventLoop)
        thread.start()
        return thread

    def EventLoop(self):
        self.api.dbgLoop()


    def subscribeEvents(self, callback, user_data=None, plug_name=""):

        observer = CDebugObserver()
        observer.userData = user_data if user_data else None
        
        def event_handler(event_ptr):
            try:
                event = event_ptr.contents
                callback(event)
            except Exception as e:
                print(f"Error in event handler: {e}")

        # Сохраняем обёртку
        observer.update = CFUNCTYPE(None, POINTER(CDebugEvent))(event_handler)
        observer.plugName = plug_name.encode('utf-8') if plug_name else b""

        # Регистрируем наблюдателя
        self.api.attach(observer)

        self._observers[callback] = observer
        return observer

    def unsubscribeEvents(self, callback):
        if callback in self._observers:
            observer = self._observers[callback]
            self.api.detach(observer)
            del self._observers[callback]
            return True
        return False

    def send_command(self, cmd: str) -> None:
        if not cmd:
            return
        encoded = cmd.encode('utf-8')
        self.api.sendCommand(encoded)

    def __del__(self):
        if hasattr(self, 'debuggerPtr') and self.debuggerPtr:
            destroyFunc = self.dll.destroyDebugger
            destroyFunc.argtypes = [c_void_p]
            destroyFunc(self.debuggerPtr)




