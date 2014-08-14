# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.api.process import Process
from lib.api.utils import Utils

class Shellcode(Package):
    """Shellcode (any x86 executable code) analysis package."""

    def start(self, path):
        gw = self.options.get("setgw",None)

        u = Utils()
        if gw:
           u.set_default_gw(gw)

        p = Process()
        dll = self.options.get("dll")
        p.execute(path="bin/execsc.exe", args=path, suspended=True)
        p.inject(dll)
        p.resume()

        return p.pid

    def check(self):
        return True

    def finish(self):
        if self.options.get("procmemdump", False):
            for pid in self.pids:
                p = Process(pid=pid)
                p.dump_memory()

        return True
