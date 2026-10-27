"""Windows job ownership for this proof's Node/browser tree only.

The child receives no stdin until it has joined the new job. Unknown HTTP
outcomes remain unknown even when every owned process has been stopped.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import re
import time

from journey_contracts import need


class _Basic(ctypes.Structure):
    _fields_ = [('process_time', ctypes.c_int64), ('job_time', ctypes.c_int64),
        ('flags', wintypes.DWORD), ('minimum_ws', ctypes.c_size_t), ('maximum_ws', ctypes.c_size_t),
        ('active_limit', wintypes.DWORD), ('affinity', ctypes.c_size_t),
        ('priority', wintypes.DWORD), ('scheduling', wintypes.DWORD)]


class _IO(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in ('reads', 'writes', 'other', 'read_bytes', 'write_bytes', 'other_bytes')]


class _Extended(ctypes.Structure):
    _fields_ = [('basic', _Basic), ('io', _IO), ('process_memory', ctypes.c_size_t),
        ('job_memory', ctypes.c_size_t), ('peak_process_memory', ctypes.c_size_t), ('peak_job_memory', ctypes.c_size_t)]


class _Accounting(ctypes.Structure):
    _fields_ = [('user', ctypes.c_int64), ('kernel', ctypes.c_int64), ('period_user', ctypes.c_int64),
        ('period_kernel', ctypes.c_int64), ('page_faults', wintypes.DWORD), ('total', wintypes.DWORD),
        ('active', wintypes.DWORD), ('terminated', wintypes.DWORD)]


class OwnedJob:
    def __init__(self):
        need(os.name == 'nt', 'WINDOWS_OWNED_BROWSER_LAUNCH_REQUIRED')
        self.api = ctypes.WinDLL('kernel32', use_last_error=True)
        self.api.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self.api.CreateJobObjectW.restype = wintypes.HANDLE
        self.api.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        self.api.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.api.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]
        self.api.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self.api.CloseHandle.argtypes = [wintypes.HANDLE]
        self.api.GetProcessTimes.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        self.api.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        self.handle = self.api.CreateJobObjectW(None, None)
        need(bool(self.handle), 'OWNED_JOB_CREATE_FAILED')
        limits = _Extended(); limits.basic.flags = 0x2000  # KILL_ON_JOB_CLOSE
        try:
            need(bool(self.api.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits))),
                 'OWNED_JOB_LIMIT_FAILED')
        except Exception:
            self.close()
            raise
        self.assigned = False

    def assign(self, process):
        need(not self.assigned and process.poll() is None and bool(getattr(process, '_handle', None)), 'OWNED_CHILD_HANDLE_REQUIRED')
        need(bool(self.api.AssignProcessToJobObject(self.handle, wintypes.HANDLE(int(process._handle)))), 'OWNED_CHILD_ASSIGNMENT_FAILED')
        self.assigned = True

    def identity(self, process):
        return process_identity(self.api, wintypes.HANDLE(int(process._handle)), process.pid)

    def active(self):
        need(bool(self.handle), 'OWNED_JOB_CLOSED')
        info = _Accounting()
        need(bool(self.api.QueryInformationJobObject(self.handle, 1, ctypes.byref(info), ctypes.sizeof(info), None)),
             'OWNED_JOB_QUERY_FAILED')
        return int(info.active)

    def stop(self):
        need(bool(self.handle), 'OWNED_JOB_CLOSED')
        if self.active():
            need(bool(self.api.TerminateJobObject(self.handle, 1)), 'OWNED_JOB_STOP_FAILED')
        deadline = time.monotonic() + 15
        while self.active() and time.monotonic() < deadline:
            time.sleep(0.05)
        need(self.active() == 0, 'OWNED_PROCESSES_EXIT_UNCONFIRMED')

    def close(self):
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None


def process_identity(api, handle, pid):
    created, exited, kernel, user = (wintypes.FILETIME() for _ in range(4))
    need(bool(api.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited), ctypes.byref(kernel), ctypes.byref(user))),
         'OWNED_PROCESS_TIMES_UNAVAILABLE')
    buffer = ctypes.create_unicode_buffer(32768); size = wintypes.DWORD(len(buffer))
    need(bool(api.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size))), 'OWNED_PROCESS_IMAGE_UNAVAILABLE')
    return {'pid': pid, 'creation_filetime': str((int(created.dwHighDateTime) << 32) | int(created.dwLowDateTime)),
            'executable': str(Path(buffer.value).absolute())}


def inspect_identity(record):
    """Read-only PID+birth+executable comparison; absence never permits replay."""
    need(os.name == 'nt' and type(record) is dict and set(record) == {'pid', 'creation_filetime', 'executable'}
         and type(record['pid']) is int and record['pid'] > 0 and type(record['creation_filetime']) is str
         and re.fullmatch('[0-9]+', record['creation_filetime']) and type(record['executable']) is str
         and Path(record['executable']).is_absolute(), 'RECORDED_PROCESS_IDENTITY_REQUIRED')
    api = ctypes.WinDLL('kernel32', use_last_error=True)
    api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]; api.OpenProcess.restype = wintypes.HANDLE
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    api.GetProcessTimes.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    api.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    api.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]; api.WaitForSingleObject.restype = wintypes.DWORD
    handle = api.OpenProcess(0x1000 | 0x100000, False, record['pid'])  # QUERY_LIMITED_INFORMATION | SYNCHRONIZE
    if not handle:
        return {'state': 'absent' if ctypes.get_last_error() == 87 else 'unconfirmed', 'automatic_replay_permitted': False}
    try:
        # A terminated process can retain an open process object while its
        # image-name query is already unavailable. Birth identity still binds
        # that object; never confuse this with a new process reusing its PID.
        created, exited, kernel, user = (wintypes.FILETIME() for _ in range(4))
        need(bool(api.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited), ctypes.byref(kernel), ctypes.byref(user))),
             'RECORDED_PROCESS_TIMES_UNAVAILABLE')
        birth = str((int(created.dwHighDateTime) << 32) | int(created.dwLowDateTime))
        if birth != record['creation_filetime']:
            return {'state': 'different_process', 'automatic_replay_permitted': False}
        waited = api.WaitForSingleObject(handle, 0)
        if waited == 0:
            return {'state': 'terminated', 'automatic_replay_permitted': False}
        if waited != 258:
            return {'state': 'unconfirmed', 'automatic_replay_permitted': False}
        try:
            actual = process_identity(api, handle, record['pid'])
        except Exception:
            # Exit may race the image query after the earlier running check.
            # The same held handle and already matched birth identity apply.
            return {'state': 'terminated' if api.WaitForSingleObject(handle, 0) == 0 else 'unconfirmed',
                    'automatic_replay_permitted': False}
        return {'state': 'running' if Path(actual['executable']) == Path(record['executable']) else 'different_process',
            'automatic_replay_permitted': False}
    finally:
        api.CloseHandle(handle)
