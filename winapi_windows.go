//go:build windows

package main

import (
	"strings"
	"syscall"
	"unsafe"
)

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	gdi32    = syscall.NewLazyDLL("gdi32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	pRegisterClassExW     = user32.NewProc("RegisterClassExW")
	pCreateWindowExW      = user32.NewProc("CreateWindowExW")
	pDefWindowProcW       = user32.NewProc("DefWindowProcW")
	pDestroyWindow        = user32.NewProc("DestroyWindow")
	pShowWindow           = user32.NewProc("ShowWindow")
	pUpdateWindow         = user32.NewProc("UpdateWindow")
	pGetMessageW          = user32.NewProc("GetMessageW")
	pTranslateMessage     = user32.NewProc("TranslateMessage")
	pDispatchMessageW     = user32.NewProc("DispatchMessageW")
	pIsDialogMessageW     = user32.NewProc("IsDialogMessageW")
	pPostMessageW         = user32.NewProc("PostMessageW")
	pSendMessageW         = user32.NewProc("SendMessageW")
	pPostQuitMessage      = user32.NewProc("PostQuitMessage")
	pMessageBoxW          = user32.NewProc("MessageBoxW")
	pEnableWindow         = user32.NewProc("EnableWindow")
	pSetWindowTextW       = user32.NewProc("SetWindowTextW")
	pGetWindowTextW       = user32.NewProc("GetWindowTextW")
	pGetWindowTextLengthW = user32.NewProc("GetWindowTextLengthW")
	pLoadIconW            = user32.NewProc("LoadIconW")
	pLoadCursorW          = user32.NewProc("LoadCursorW")
	pGetDC                = user32.NewProc("GetDC")
	pReleaseDC            = user32.NewProc("ReleaseDC")
	pGetSysColor          = user32.NewProc("GetSysColor")
	pGetSysColorBrush     = user32.NewProc("GetSysColorBrush")
	pGetSystemMetrics     = user32.NewProc("GetSystemMetrics")
	pSetProcessDPIAware   = user32.NewProc("SetProcessDPIAware")
	pAdjustWindowRectEx   = user32.NewProc("AdjustWindowRectEx")
	pInvalidateRect       = user32.NewProc("InvalidateRect")
	pGetFocus             = user32.NewProc("GetFocus")
	pSetForegroundWindow  = user32.NewProc("SetForegroundWindow")
	pFindWindowW          = user32.NewProc("FindWindowW")
	pSetFocus             = user32.NewProc("SetFocus")

	pCreateFontW    = gdi32.NewProc("CreateFontW")
	pGetDeviceCaps  = gdi32.NewProc("GetDeviceCaps")
	pSetTextColor   = gdi32.NewProc("SetTextColor")
	pSetBkColor     = gdi32.NewProc("SetBkColor")
	pGetStockObject = gdi32.NewProc("GetStockObject")

	pGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")
	pCreateMutexW     = kernel32.NewProc("CreateMutexW")
	pCloseHandle      = kernel32.NewProc("CloseHandle")
)

const (
	WS_OVERLAPPED       = 0x00000000
	WS_CAPTION          = 0x00C00000
	WS_SYSMENU          = 0x00080000
	WS_MINIMIZEBOX      = 0x00020000
	WS_CHILD            = 0x40000000
	WS_VISIBLE          = 0x10000000
	WS_TABSTOP          = 0x00010000
	WS_GROUP            = 0x00020000
	WS_VSCROLL          = 0x00200000
	WS_EX_CLIENTEDGE    = 0x00000200
	WS_EX_LAYOUTRTL     = 0x00400000
	WS_EX_CONTROLPARENT = 0x00010000

	BS_PUSHBUTTON    = 0x0
	BS_DEFPUSHBUTTON = 0x1
	BS_AUTOCHECKBOX  = 0x3
	BS_GROUPBOX      = 0x7
	BS_MULTILINE     = 0x2000

	ES_MULTILINE   = 0x0004
	ES_AUTOVSCROLL = 0x0040
	ES_AUTOHSCROLL = 0x0080
	ES_READONLY    = 0x0800

	LBS_NOTIFY           = 0x0001
	LBS_NOINTEGRALHEIGHT = 0x0100

	WM_DESTROY         = 0x0002
	WM_CLOSE           = 0x0010
	WM_SETFONT         = 0x0030
	WM_COMMAND         = 0x0111
	WM_CTLCOLOREDIT    = 0x0133
	WM_CTLCOLORLISTBOX = 0x0134
	WM_CTLCOLORSTATIC  = 0x0138
	WM_APP             = 0x8000

	BN_CLICKED      = 0
	LBN_DBLCLK      = 2
	BM_GETCHECK     = 0x00F0
	BM_SETCHECK     = 0x00F1
	BST_CHECKED     = 1
	EM_SETSEL       = 0x00B1
	EM_REPLACESEL   = 0x00C2
	EM_SETLIMITTEXT = 0x00C5
	EM_SCROLLCARET  = 0x00B7
	LB_ADDSTRING    = 0x0180
	LB_RESETCONTENT = 0x0184
	LB_GETCURSEL    = 0x0188
	LB_SETCURSEL    = 0x0186

	MB_OK            = 0x00000000
	MB_YESNO         = 0x00000004
	MB_ICONERROR     = 0x00000010
	MB_ICONQUESTION  = 0x00000020
	MB_ICONWARNING   = 0x00000030
	MB_ICONINFO      = 0x00000040
	MB_DEFBUTTON2    = 0x00000100
	MB_SETFOREGROUND = 0x00010000
	MB_RIGHT         = 0x00080000
	MB_RTLREADING    = 0x00100000
	IDYES            = 6
	IDOK             = 1

	COLOR_BTNFACE = 15
	WHITE_BRUSH   = 0
	LOGPIXELSX    = 88
	SM_CXSCREEN   = 0
	SM_CYSCREEN   = 1
	SW_SHOW       = 5
	IDC_ARROW     = 32512

	ERROR_ALREADY_EXISTS = 183
)

type WNDCLASSEXW struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     uintptr
	HIcon         uintptr
	HCursor       uintptr
	HbrBackground uintptr
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       uintptr
}

type POINT struct{ X, Y int32 }

type MSG struct {
	HWnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      POINT
	Private uint32
}

type RECT struct{ Left, Top, Right, Bottom int32 }

func u16(s string) *uint16 {
	p, err := syscall.UTF16PtrFromString(s)
	if err != nil {
		p, _ = syscall.UTF16PtrFromString("?")
	}
	return p
}

func sendMessage(h uintptr, msg uint32, w, l uintptr) uintptr {
	r, _, _ := pSendMessageW.Call(h, uintptr(msg), w, l)
	return r
}

func postMessage(h uintptr, msg uint32, w, l uintptr) {
	pPostMessageW.Call(h, uintptr(msg), w, l)
}

func setText(h uintptr, s string) {
	p := u16(s)
	pSetWindowTextW.Call(h, uintptr(unsafe.Pointer(p)))
}

func getText(h uintptr) string {
	n, _, _ := pGetWindowTextLengthW.Call(h)
	if n == 0 {
		return ""
	}
	buf := make([]uint16, n+1)
	pGetWindowTextW.Call(h, uintptr(unsafe.Pointer(&buf[0])), n+1)
	return syscall.UTF16ToString(buf)
}

func enable(h uintptr, on bool) {
	v := uintptr(0)
	if on {
		v = 1
	}
	pEnableWindow.Call(h, v)
}

func messageBox(owner uintptr, text, title string, flags uintptr) int {
	t := u16(rtlText(text))
	c := u16(title)
	r, _, _ := pMessageBoxW.Call(owner, uintptr(unsafe.Pointer(t)), uintptr(unsafe.Pointer(c)),
		flags|rtlBoxFlags()|MB_SETFOREGROUND)
	return int(r)
}

func rgb(r, g, b byte) uint32 { return uint32(r) | uint32(g)<<8 | uint32(b)<<16 }

func unsafePtr(s string) unsafe.Pointer { return unsafe.Pointer(u16(s)) }

// ---------------------------------------------------------------- common controls, dialogs

var (
	comctl32 = syscall.NewLazyDLL("comctl32.dll")
	comdlg32 = syscall.NewLazyDLL("comdlg32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")
	ole32    = syscall.NewLazyDLL("ole32.dll")

	pInitCommonControlsEx = comctl32.NewProc("InitCommonControlsEx")
	pGetOpenFileNameW     = comdlg32.NewProc("GetOpenFileNameW")
	pShellExecuteW        = shell32.NewProc("ShellExecuteW")
	pCoInitializeEx       = ole32.NewProc("CoInitializeEx")
)

const (
	WM_NOTIFY = 0x004E

	LVS_REPORT           = 0x0001
	LVS_SINGLESEL        = 0x0004
	LVS_SHOWSELALWAYS    = 0x0008
	LVS_NOSORTHEADER     = 0x8000
	LVS_EX_FULLROWSELECT = 0x00000020

	LVM_DELETEALLITEMS           = 0x1009
	LVM_GETNEXTITEM              = 0x100C
	LVM_SETEXTENDEDLISTVIEWSTYLE = 0x1036
	LVM_INSERTITEMW              = 0x104D
	LVM_INSERTCOLUMNW            = 0x1061
	LVM_SETITEMTEXTW             = 0x1074
	LVNI_SELECTED                = 0x0002

	LVCF_FMT   = 0x1
	LVCF_WIDTH = 0x2
	LVCF_TEXT  = 0x4
	LVIF_TEXT  = 0x1
	LVIF_PARAM = 0x4

	NM_CUSTOMDRAW       = -12
	CDDS_PREPAINT       = 0x00000001
	CDDS_ITEMPREPAINT   = 0x00010001
	CDRF_DODEFAULT      = 0x0
	CDRF_NEWFONT        = 0x2
	CDRF_NOTIFYITEMDRAW = 0x20

	OFN_HIDEREADONLY  = 0x00000004
	OFN_NOCHANGEDIR   = 0x00000008
	OFN_PATHMUSTEXIST = 0x00000800
	OFN_FILEMUSTEXIST = 0x00001000
)

type INITCOMMONCONTROLSEX struct {
	Size uint32
	ICC  uint32
}

type LVCOLUMNW struct {
	Mask      uint32
	Fmt       int32
	Cx        int32
	PszText   *uint16
	CchText   int32
	ISubItem  int32
	IImage    int32
	IOrder    int32
	CxMin     int32
	CxDefault int32
	CxIdeal   int32
}

type LVITEMW struct {
	Mask      uint32
	IItem     int32
	ISubItem  int32
	State     uint32
	StateMask uint32
	PszText   *uint16
	CchText   int32
	IImage    int32
	LParam    uintptr
	IIndent   int32
	IGroupId  int32
	CColumns  uint32
	PuColumns *uint32
	PiColFmt  *int32
	IGroup    int32
}

type NMHDR struct {
	HwndFrom uintptr
	IdFrom   uintptr
	Code     int32
}

type NMCUSTOMDRAW struct {
	Hdr        NMHDR
	DrawStage  uint32
	Hdc        uintptr
	Rc         RECT
	ItemSpec   uintptr
	ItemState  uint32
	ItemlParam uintptr
}

type NMLVCUSTOMDRAW struct {
	Nmcd      NMCUSTOMDRAW
	ClrText   uint32
	ClrTextBk uint32
	ISubItem  int32
}

type OPENFILENAMEW struct {
	StructSize    uint32
	Owner         uintptr
	Instance      uintptr
	Filter        *uint16
	CustomFilter  *uint16
	MaxCustFilter uint32
	FilterIndex   uint32
	File          *uint16
	MaxFile       uint32
	FileTitle     *uint16
	MaxFileTitle  uint32
	InitialDir    *uint16
	Title         *uint16
	Flags         uint32
	FileOffset    uint16
	FileExtension uint16
	DefExt        *uint16
	CustData      uintptr
	FnHook        uintptr
	TemplateName  *uint16
	PvReserved    uintptr
	DwReserved    uint32
	FlagsEx       uint32
}

// asPtr turns a message parameter into a pointer without upsetting vet.
func asPtr(v uintptr) unsafe.Pointer { return *(*unsafe.Pointer)(unsafe.Pointer(&v)) }

// utf16z builds a UTF-16 buffer that may contain inner NULs (file filters).
func utf16z(parts ...string) []uint16 {
	var out []uint16
	for _, p := range parts {
		u, _ := syscall.UTF16FromString(p)
		out = append(out, u...) // includes the terminating 0
	}
	return append(out, 0)
}

var (
	pCreateSolidBrush = gdi32.NewProc("CreateSolidBrush")
	pSetWindowPos     = user32.NewProc("SetWindowPos")
)

const (
	WS_CLIPSIBLINGS = 0x04000000
	SW_HIDE         = 0
	SWP_NOMOVE      = 0x0002
	SWP_NOZORDER    = 0x0004
	SS_NOPREFIX     = 0x0080
)

func show(h uintptr, on bool) {
	if on {
		pShowWindow.Call(h, SW_SHOW)
	} else {
		pShowWindow.Call(h, SW_HIDE)
	}
}

func solidBrush(c uint32) uintptr {
	b, _, _ := pCreateSolidBrush.Call(uintptr(c))
	return b
}

var (
	pFillRect      = user32.NewProc("FillRect")
	pGetClientRect = user32.NewProc("GetClientRect")
)

const (
	WS_CLIPCHILDREN = 0x02000000
	WM_ERASEBKGND   = 0x0014
)

var (
	pSystemParametersInfoW = user32.NewProc("SystemParametersInfoW")
	pDrawTextW             = user32.NewProc("DrawTextW")
	pMoveWindow            = user32.NewProc("MoveWindow")
	pGetWindowRect         = user32.NewProc("GetWindowRect")
	pIsWindowVisible       = user32.NewProc("IsWindowVisible")
	pGetParent             = user32.NewProc("GetParent")
	pOpenClipboard         = user32.NewProc("OpenClipboard")
	pCloseClipboard        = user32.NewProc("CloseClipboard")
	pEmptyClipboard        = user32.NewProc("EmptyClipboard")
	pSetClipboardData      = user32.NewProc("SetClipboardData")
	pSelectObject          = gdi32.NewProc("SelectObject")
	pGlobalAlloc           = kernel32.NewProc("GlobalAlloc")
	pGlobalLock            = kernel32.NewProc("GlobalLock")
	pGlobalUnlock          = kernel32.NewProc("GlobalUnlock")
	pGlobalFree            = kernel32.NewProc("GlobalFree")
)

const (
	SPI_GETWORKAREA = 0x0030
	SWP_NOACTIVATE  = 0x0010

	DT_WORDBREAK  = 0x00000010
	DT_CALCRECT   = 0x00000400
	DT_NOPREFIX   = 0x00000800
	DT_RTLREADING = 0x00020000

	WM_CTLCOLORBTN = 0x0135

	PBS_MARQUEE    = 0x08
	PBM_SETMARQUEE = 0x040A

	CBS_DROPDOWN       = 0x0002
	CBS_AUTOHSCROLL    = 0x0040
	CB_SETEDITSEL      = 0x0142
	CB_ADDSTRING       = 0x0143
	CB_GETCURSEL       = 0x0147
	CB_SETDROPPEDWIDTH = 0x0160
	CB_SETCUEBANNER    = 0x1703
	CB_SETMINVISIBLE   = 0x1701
	LVM_ENSUREVISIBLE  = 0x1013
	CB_SETCURSEL       = 0x014E
	CBS_DROPDOWNLIST   = 0x0003
	CBN_SELCHANGE      = 1
	LBN_SELCHANGE      = 1

	LVS_EX_DOUBLEBUFFER    = 0x00010000
	LVM_SETITEMSTATE       = 0x102B
	LVIS_FOCUSED           = 0x1
	LVIS_SELECTED          = 0x2
	CDDS_SUBITEM           = 0x00020000
	CDRF_NOTIFYSUBITEMDRAW = 0x20
	LVN_ITEMCHANGED        = -101
	LVN_KEYDOWN            = -155
	VK_DELETE              = 0x2E

	GMEM_MOVEABLE  = 0x0002
	CF_UNICODETEXT = 13
)

// NMLVKEYDOWN is 1-byte packed in C: only VKey (offset 24) is read here.
type NMLVKEYDOWN struct {
	Hdr   NMHDR
	VKey  uint16
	Flags uint32
}

var pSetWindowTheme = syscall.NewLazyDLL("uxtheme.dll").NewProc("SetWindowTheme")

var (
	pIsWindowEnabled            = user32.NewProc("IsWindowEnabled")
	pGetDoubleClickTime         = user32.NewProc("GetDoubleClickTime")
	pShutdownBlockReasonCreate  = user32.NewProc("ShutdownBlockReasonCreate")
	pShutdownBlockReasonDestroy = user32.NewProc("ShutdownBlockReasonDestroy")
	pGetTickCount               = kernel32.NewProc("GetTickCount")
)

const WM_QUERYENDSESSION = 0x0011

// rtlBoxFlags: message boxes read right to left only in Persian.
func rtlBoxFlags() uintptr {
	if lang == "fa" {
		return MB_RTLREADING | MB_RIGHT
	}
	return 0
}

// regionCountry: the two-letter code of the country set in Windows
// (Settings, Time & Language, Region), to preselect it in the list.
func regionCountry() string {
	r, _, _ := kernel32.NewProc("GetUserGeoID").Call(16) // GEOCLASS_NATION
	geo := uintptr(uint32(r))
	if geo == 0 || geo == 0xFFFFFFFF {
		return ""
	}
	buf := make([]uint16, 8)
	n, _, _ := kernel32.NewProc("GetGeoInfoW").Call(geo, 4 /*GEO_ISO2*/, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0)
	if n == 0 {
		return ""
	}
	return strings.ToUpper(syscall.UTF16ToString(buf))
}
