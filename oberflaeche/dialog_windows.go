//go:build windows

package oberflaeche

import (
	"syscall"
	"unsafe"
)

const (
	_ uintptr = 152 - unsafe.Sizeof(openName{})
	_ uintptr = unsafe.Sizeof(openName{}) - 152
	_ uintptr = 64 - unsafe.Sizeof(browseInfo{})
	_ uintptr = unsafe.Sizeof(browseInfo{}) - 64
)

var (
	comdlg32         = syscall.NewLazyDLL("comdlg32.dll")
	shell32          = syscall.NewLazyDLL("shell32.dll")
	ole32            = syscall.NewLazyDLL("ole32.dll")
	getOpenFileNameW = comdlg32.NewProc("GetOpenFileNameW")
	browseForFolder  = shell32.NewProc("SHBrowseForFolderW")
	getPathFromID    = shell32.NewProc("SHGetPathFromIDListW")
	coTaskMemFree    = ole32.NewProc("CoTaskMemFree")
	coInitializeEx   = ole32.NewProc("CoInitializeEx")
)

type openName struct {
	structSize      uint32
	owner           uintptr
	instance        uintptr
	filter          *uint16
	customFilter    *uint16
	maxCustomFilter uint32
	filterIndex     uint32
	file            *uint16
	maxFile         uint32
	fileTitle       *uint16
	maxFileTitle    uint32
	initialDir      *uint16
	title           *uint16
	flags           uint32
	fileOffset      uint16
	fileExtension   uint16
	defExt          *uint16
	custData        uintptr
	fnHook          uintptr
	templateName    *uint16
	reserved        uintptr
	reservedFlags   uint32
	flagsEx         uint32
}

type browseInfo struct {
	owner       uintptr
	root        uintptr
	displayName *uint16
	title       *uint16
	flags       uint32
	callback    uintptr
	param       uintptr
	image       int32
}

const (
	ofnFileMustExist = 0x00001000
	ofnPathMustExist = 0x00000800
	ofnNoChangeDir   = 0x00000008
	ofnExplorer      = 0x00080000
	bifOnlyDirs      = 0x00000001
	bifNewDialog     = 0x00000040
)

func dateiWaehlen(titel string) (string, bool) {
	filter := utf16Liste("Schlüssel", "*.pem;*.pk8", "Alle Dateien", "*.*")
	name := make([]uint16, 32768)
	titelU, err := syscall.UTF16PtrFromString(titel)
	if err != nil {
		return "", false
	}
	ofn := openName{
		structSize: uint32(unsafe.Sizeof(openName{})),
		filter:     &filter[0],
		file:       &name[0],
		maxFile:    uint32(len(name)),
		title:      titelU,
		flags:      ofnFileMustExist | ofnPathMustExist | ofnNoChangeDir | ofnExplorer,
	}
	r, _, _ := getOpenFileNameW.Call(uintptr(unsafe.Pointer(&ofn)))
	if r == 0 {
		return "", false
	}
	return syscall.UTF16ToString(name), true
}

func ordnerWaehlen(titel string) (string, bool) {
	_, _, _ = coInitializeEx.Call(0, 2)
	titelU, err := syscall.UTF16PtrFromString(titel)
	if err != nil {
		return "", false
	}
	anzeige := make([]uint16, 260)
	info := browseInfo{
		displayName: &anzeige[0],
		title:       titelU,
		flags:       bifOnlyDirs | bifNewDialog,
	}
	pidl, _, _ := browseForFolder.Call(uintptr(unsafe.Pointer(&info)))
	if pidl == 0 {
		return "", false
	}
	defer coTaskMemFree.Call(pidl)
	pfad := make([]uint16, 260)
	r, _, _ := getPathFromID.Call(pidl, uintptr(unsafe.Pointer(&pfad[0])))
	if r == 0 {
		return "", false
	}
	return syscall.UTF16ToString(pfad), true
}

func utf16Liste(teile ...string) []uint16 {
	var u []uint16
	for _, teil := range teile {
		p, err := syscall.UTF16FromString(teil)
		if err != nil || len(p) == 0 {
			continue
		}
		u = append(u, p[:len(p)-1]...)
		u = append(u, 0)
	}
	u = append(u, 0)
	return u
}
