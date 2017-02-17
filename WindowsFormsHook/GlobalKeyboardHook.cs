using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace WindowsFormsHook
{

    public enum Code : Int32 //for CBT
    {
        HCBT_ACTIVATE = 5,
        HCBT_CLICKSKIPPED = 6,
        HCBT_CREATEWND = 3,
        HCBT_DESTROYWND = 4,
        HCBT_KEYSKIPPED = 7,
        HCBT_MINMAX = 1,          //действия при сворачивании/разворачивании
        HCBT_MOVESIZE = 0,
        HCBT_QS = 2,
        HCBT_SETFOCUS = 9,
        HCBT_SYSCOMMAND = 8
    }

    public enum CmdShow : Int32 //for CBT
    {
        SW_FORCEMINIMIZE = 11,
        SW_HIDE = 0,
        SW_MAXIMIZE = 3,
        SW_MINIMIZE = 6,
        SW_RESTORE = 9,
        SW_SHOW = 5,
        SW_SHOWDEFAULT = 10,
        SW_SHOWMAXIMIZED = 3,
        SW_SHOWMINIMIZED = 2,
        SW_SHOWMINNOACTIVE = 7,
        SW_SHOWNA = 8,
        SW_SHOWNOACTIVATE = 4,
        SW_SHOWNORMAL = 1
    }

    public enum HookType : Int32
    {
        WH_CALLWNDPROC =     4,
        WH_CALLWNDPROCRET = 12,
        WH_CBT =             5,
        WH_DEBUG =           9,
        WH_FOREGROUNDIDLE = 11,
        WH_GETMESSAGE =      3,
        WH_JOURNALPLAYBACK = 1,
        WH_JOURNALRECORD =   0,
        WH_KEYBOARD =        2,
        WH_KEYBOARD_LL =    13,
        WH_MOUSE =           7,
        WH_MOUSE_LL =       14,
        WH_MSGFILTER =      -1,
        WH_SHELL =          10,
        WH_SYSMSGFILTER =    6,
        WH_HARDWARE =        8,       
    }

    delegate IntPtr HookProc(Int32 code, IntPtr wParam, IntPtr lParam);

    //Структура хук точек
    struct HOOK {
        public HookType nType;  //тип точки
        public HookProc hProc;  //процедура обработки
        public IntPtr hHook;    //дескриптор хук точки
    }

    class GlobalKeyboardHook
    {
        //константы для структур
        const Byte IDM_CALLWNDPROC = 0,
                   IDM_CALLWNDPROCRET = 1,
                   IDM_CBT = 2,
                   IDM_DEBUG = 3,
                   IDM_FOREGROUNDIDLE = 4,
                   IDM_GETMESSAGE = 5,
                   IDM_JOURNALPLAYBACK = 6,
                   IDM_JOURNALRECORD = 7,
                   IDM_KEYBOARD = 8,
                   IDM_KEYBOARD_LL = 9,
                   IDM_MOUSE = 10,
                   IDM_MOUSE_LL = 11,
                   IDM_MSGFILTER = 12,
                   IDM_SHELL = 13,
                   IDM_SYSMSGFILTER = 14,
                   IDM_HARDWARE = 15,
                   SizeHookData = 16;

        HOOK[] HookData = new HOOK[SizeHookData];
            
             
        IntPtr hhook = IntPtr.Zero;



        public GlobalKeyboardHook()
        {
            //Инициализация хук точек
            HookData[IDM_CALLWNDPROC] = new HOOK { nType = HookType.WH_CALLWNDPROC, hProc = CallWNDProc, hHook = IntPtr.Zero };
            HookData[IDM_CALLWNDPROCRET] = new HOOK { nType = HookType.WH_CALLWNDPROCRET, hProc = CallWNDProcRet, hHook = IntPtr.Zero };
            HookData[IDM_CBT] = new HOOK { nType = HookType.WH_CBT, hProc = CBT, hHook = IntPtr.Zero };
            HookData[IDM_DEBUG] = new HOOK { nType = HookType.WH_DEBUG, hProc = DEBUG, hHook = IntPtr.Zero };
            HookData[IDM_FOREGROUNDIDLE] = new HOOK { nType = HookType.WH_FOREGROUNDIDLE, hProc = FOREGROUNDIDLE, hHook = IntPtr.Zero };
            HookData[IDM_GETMESSAGE] = new HOOK { nType = HookType.WH_GETMESSAGE, hProc = GETMESSAGE, hHook = IntPtr.Zero };
            HookData[IDM_JOURNALPLAYBACK] = new HOOK { nType = HookType.WH_JOURNALPLAYBACK, hProc = JOURNALPLAYBACK, hHook = IntPtr.Zero };
            HookData[IDM_JOURNALRECORD] = new HOOK { nType = HookType.WH_JOURNALRECORD, hProc = JOURNALRECORD, hHook = IntPtr.Zero };
            HookData[IDM_KEYBOARD] = new HOOK { nType = HookType.WH_KEYBOARD, hProc = KEYBOARD, hHook = IntPtr.Zero };
            HookData[IDM_KEYBOARD_LL] = new HOOK { nType = HookType.WH_KEYBOARD_LL, hProc = KEYBOARD_LL, hHook = IntPtr.Zero };
            HookData[IDM_MOUSE] = new HOOK { nType = HookType.WH_MOUSE, hProc = MOUSE, hHook = IntPtr.Zero };
            HookData[IDM_MOUSE_LL] = new HOOK { nType = HookType.WH_MOUSE_LL, hProc = MOUSE_LL, hHook = IntPtr.Zero };
            HookData[IDM_MSGFILTER] = new HOOK { nType = HookType.WH_MSGFILTER, hProc = MSGFILTER, hHook = IntPtr.Zero };
            HookData[IDM_SHELL] = new HOOK { nType = HookType.WH_SHELL, hProc = SHELL, hHook = IntPtr.Zero };
            HookData[IDM_SYSMSGFILTER] = new HOOK { nType = HookType.WH_SYSMSGFILTER, hProc = SYSMSGFILTER, hHook = IntPtr.Zero };
            HookData[IDM_HARDWARE] = new HOOK { nType = HookType.WH_HARDWARE, hProc = HARDWARE, hHook = IntPtr.Zero };

            //установить хук 




            IntPtr hInstance = LoadLibrary("User32");
            //HookData[IDM_KEYBOARD_LL].hHook = SetWindowsHookEx(HookData[IDM_KEYBOARD_LL].nType, HookData[IDM_KEYBOARD_LL].hProc, hInstance, 0);
            //HookData[IDM_MOUSE_LL].hHook = SetWindowsHookEx(HookData[IDM_MOUSE_LL].nType, HookData[IDM_MOUSE_LL].hProc, hInstance, 0);
            HookData[IDM_CBT].hHook = SetWindowsHookEx(HookData[IDM_CBT].nType, HookData[IDM_CBT].hProc, hInstance, 0);
        }

        ~GlobalKeyboardHook()
        {
            UnhookWindowsHookEx(hhook);
        }

        


        #region Процедуры
        static IntPtr CallWNDProc(Int32 nCode, IntPtr wParam, IntPtr lParam)
        {         
            return CallNextHookEx(IntPtr.Zero, nCode, wParam, lParam);
        }
        static IntPtr CallWNDProcRet(Int32 nCode, IntPtr wParam, IntPtr lParam)
        {
            return CallNextHookEx(IntPtr.Zero, nCode, wParam, lParam);
        }
        static IntPtr CBT(Int32 nCode, IntPtr wParam, IntPtr lParam)
        {
            //wParam - дескриптор окна 
            switch ((Code)nCode)
            {
                case Code.HCBT_ACTIVATE:    break;
                case Code.HCBT_CLICKSKIPPED: break;
                case Code.HCBT_CREATEWND: break;
                case Code.HCBT_DESTROYWND:  break;
                case Code.HCBT_KEYSKIPPED: break;
                case Code.HCBT_MINMAX: 
                    {
                        switch ((CmdShow)lParam)
                        {
                            case CmdShow.SW_FORCEMINIMIZE: break;
                            case CmdShow.SW_HIDE: break;
                            case CmdShow.SW_MAXIMIZE: { MessageBox.Show("Окно разворачивается", "СВТ -> HCBT_MINMAX"); break; }
                            case CmdShow.SW_MINIMIZE: { MessageBox.Show("Окно сворачивается", "СВТ -> HCBT_MINMAX"); break; }
                        }
                        
                        //MessageBox.Show("","СВТ -> HCBT_MINMAX");
                        break;

                    }
                case Code.HCBT_MOVESIZE: break;
                case Code.HCBT_QS: break;
                case Code.HCBT_SETFOCUS: break;
                case Code.HCBT_SYSCOMMAND: break;
                default:                         throw new NotImplementedException();
            }

            return CallNextHookEx(IntPtr.Zero, nCode, wParam, lParam);
        }
        static IntPtr DEBUG(Int32 nCode, IntPtr wParam, IntPtr lParam)
        {
            return CallNextHookEx(IntPtr.Zero, nCode, wParam, lParam);
        }
        static IntPtr FOREGROUNDIDLE(Int32 nCode, IntPtr wParam, IntPtr lParam)
        {
            return CallNextHookEx(IntPtr.Zero, nCode, wParam, lParam);
        }
        static IntPtr GETMESSAGE(Int32 nCode, IntPtr wParam, IntPtr lParam)
        {
            return CallNextHookEx(IntPtr.Zero, nCode, wParam, lParam);
        }
        static IntPtr JOURNALPLAYBACK(Int32 nCode, IntPtr wParam, IntPtr lParam)
        {
            return CallNextHookEx(IntPtr.Zero, nCode, wParam, lParam);
        }
        static IntPtr JOURNALRECORD(Int32 nCode, IntPtr wParam, IntPtr lParam)
        {
            return CallNextHookEx(IntPtr.Zero, nCode, wParam, lParam);
        }
        static IntPtr KEYBOARD(Int32 nCode, IntPtr wParam, IntPtr lParam)
        {
            return CallNextHookEx(IntPtr.Zero, nCode, wParam, lParam);
        }
        static IntPtr KEYBOARD_LL(Int32 nCode, IntPtr wParam, IntPtr lParam)
        {
            KBDLLHOOKSTRUCT kbd = (KBDLLHOOKSTRUCT)Marshal.PtrToStructure(lParam, typeof(KBDLLHOOKSTRUCT));

            switch ((WindowsMessage)wParam)
            {
                case WindowsMessage.WM_KEYDOWN:    
                case WindowsMessage.WM_KEYUP:       
                case WindowsMessage.WM_SYSKEYDOWN:                    
                case WindowsMessage.WM_SYSKEYUP:    
                default:                            throw new NotImplementedException();                    
            }
            return CallNextHookEx(IntPtr.Zero, nCode, wParam, lParam);
        }
        static IntPtr MOUSE(Int32 nCode, IntPtr wParam, IntPtr lParam)
        {
            return CallNextHookEx(IntPtr.Zero, nCode, wParam, lParam);
        }
        static IntPtr MOUSE_LL(Int32 nCode, IntPtr wParam, IntPtr lParam)
        {
            MSLLHOOKSTRUCT msl = (MSLLHOOKSTRUCT)Marshal.PtrToStructure(lParam, typeof(MSLLHOOKSTRUCT));

            switch ((WindowsMessage)wParam)
            {
                case WindowsMessage.WM_LBUTTONDOWN: 
                case WindowsMessage.WM_LBUTTONUP:
                case WindowsMessage.WM_MOUSEMOVE:
                case WindowsMessage.WM_MOUSEWHEEL:
                case WindowsMessage.WM_MOUSEHWHEEL:
                case WindowsMessage.WM_RBUTTONDOWN:
                case WindowsMessage.WM_RBUTTONUP:        
                default:                                throw new NotImplementedException();

            }
            return CallNextHookEx(IntPtr.Zero, nCode, wParam, lParam);
        }
        static IntPtr MSGFILTER(Int32 nCode, IntPtr wParam, IntPtr lParam)
        {
            return CallNextHookEx(IntPtr.Zero, nCode, wParam, lParam);
        }
        static IntPtr SHELL(Int32 nCode, IntPtr wParam, IntPtr lParam)
        {
            return CallNextHookEx(IntPtr.Zero, nCode, wParam, lParam);
        }
        static IntPtr SYSMSGFILTER(Int32 nCode, IntPtr wParam, IntPtr lParam)
        {
            return CallNextHookEx(IntPtr.Zero, nCode, wParam, lParam);
        }
        static IntPtr HARDWARE(Int32 nCode, IntPtr wParam, IntPtr lParam)
        {
            return CallNextHookEx(IntPtr.Zero, nCode, wParam, lParam);
        }
        //далее
        #endregion









        [DllImport("user32.dll")]
        protected static extern IntPtr SetWindowsHookEx(
            HookType code, //Определяет тип устанавливаемой процедуры фильтра (hook)
            HookProc func, //Указатель на процедуру фильтра (hook).
            IntPtr hInstance, //Дескриптор DLL, содержащий процедуры фильтра (hook)
            Int32 threadID); //Устанавливает идентификатор потока с которым, процедура фильтра (hook) должна быть связана.

        [DllImport("user32.dll")]
        static extern bool UnhookWindowsHookEx(IntPtr hInstance);


        //CallNextHookEx
        [DllImport("user32.dll")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, Int32 nCode, IntPtr wParam, IntPtr lParam);

        // overload for use with LowLevelKeyboardProc
        [DllImport("user32.dll")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, Int32 nCode, IntPtr wParam, [In]KBDLLHOOKSTRUCT lParam);

        // overload for use with LowLevelMouseProc
        [DllImport("user32.dll")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, Int32 nCode, IntPtr wParam, [In]MSLLHOOKSTRUCT lParam);

        //Клавиатура
        [StructLayout(LayoutKind.Sequential)]
        public class KBDLLHOOKSTRUCT
        {
            public UInt32 vkCode;
            public UInt32 scanCode;
            public KBDLLHOOKSTRUCTFlags flags;
            public UInt32 time;
            public UIntPtr dwExtraInfo;
        }

        [Flags]
        public enum KBDLLHOOKSTRUCTFlags : UInt32
        {
            LLKHF_EXTENDED = 0x01,
            LLKHF_INJECTED = 0x10,
            LLKHF_ALTDOWN = 0x20,
            LLKHF_UP = 0x80,
        }

        //мышь
        [StructLayout(LayoutKind.Sequential)]
        public struct MSLLHOOKSTRUCT
        {
            public POINT pt;
            public int mouseData; // be careful, this must be ints, not uints (was wrong before I changed it...). regards, cmew.
            public int flags;
            public int time;
            public UIntPtr dwExtraInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct POINT
        {
            public int X;
            public int Y;

            public POINT(int x, int y)
            {
                this.X = x;
                this.Y = y;
            }
        }

        //private static IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam)
        //{
        //    if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN)
        //    {
        //        KBDLLHOOKSTRUCT kbd = (KBDLLHOOKSTRUCT)Marshal.PtrToStructure(lParam, typeof(KBDLLHOOKSTRUCT));
        //        Debug.WriteLine(kbd.vkCode);  // ***** your code here *****
        //    }
        //    return CallNextHookEx(_hookID, nCode, wParam, lParam);
        //}




        [DllImport("kernel32.dll")]
        static extern IntPtr LoadLibrary(string lpFileName);

    }
}
