// Package utils provides Windows-specific utilities for FIR.
package utils

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// IsAdmin checks whether the current process is running with elevated (admin) privileges.
func IsAdmin() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	member, err := windows.Token(0).IsMember(sid)
	if err != nil {
		return false
	}
	return member
}

// EnablePrivilege enables the specified privilege (e.g., "SeBackupPrivilege")
// in the current process token.
func EnablePrivilege(name string) error {
	var token windows.Token
	proc := windows.CurrentProcess()
	err := windows.OpenProcessToken(proc, windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	if err != nil {
		return fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer token.Close()

	var luid windows.LUID
	privName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString: %w", err)
	}
	err = windows.LookupPrivilegeValue(nil, privName, &luid)
	if err != nil {
		return fmt.Errorf("LookupPrivilegeValue(%s): %w", name, err)
	}

	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
	}
	tp.Privileges[0] = windows.LUIDAndAttributes{
		Luid:       luid,
		Attributes: windows.SE_PRIVILEGE_ENABLED,
	}

	err = windows.AdjustTokenPrivileges(
		token,
		false,
		&tp,
		uint32(unsafe.Sizeof(tp)),
		nil,
		nil,
	)
	if err != nil {
		return fmt.Errorf("AdjustTokenPrivileges(%s): %w", name, err)
	}
	if lastErr := windows.GetLastError(); lastErr == windows.ERROR_NOT_ALL_ASSIGNED {
		return fmt.Errorf("AdjustTokenPrivileges(%s): %w", name, lastErr)
	}

	return nil
}

// EnableForensicPrivileges enables the standard DFIR privileges:
// SeBackupPrivilege/SeRestorePrivilege (backup APIs and hive save),
// SeSecurityPrivilege (SACL/system objects), and SeDebugPrivilege.
func EnableForensicPrivileges() []error {
	privs := []string{
		"SeBackupPrivilege",
		"SeRestorePrivilege",
		"SeSecurityPrivilege",
		"SeDebugPrivilege",
	}

	var errs []error
	for _, p := range privs {
		if err := EnablePrivilege(p); err != nil {
			errs = append(errs, fmt.Errorf("enable %s: %w", p, err))
		}
	}
	return errs
}
