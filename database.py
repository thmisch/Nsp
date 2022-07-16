"""
Copyright (C) 2022 themisch

This file is part of Nsc.
Nsc is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

Nsc is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along with Nsc.
If not, see <https://www.gnu.org/licenses/>.
"""

import pickle, os, shutil
from nacl.secret import SecretBox

class PersistentDict(dict):
    """Persistent dictionary with an API compatible with shelve and anydbm.

    The dict is kept in memory, so the dictionary operations run as fast as
    a regular dictionary.

    Write to disk is delayed until close or sync (similar to gdbm's fast mode).
    """

    def __init__(self, filename, key, flag="c", mode=None, *args, **kwds):
        self.flag = flag  # r=readonly, c=create, or n=new
        self.mode = mode  # None or an octal triple like 0644
        self.box = SecretBox(key)
        self.filename = filename
        if flag != "n" and os.access(filename, os.R_OK):
            fileobj = open(filename, "rb")
            with fileobj:
                self.load(fileobj)
        dict.__init__(self, *args, **kwds)

    def sync(self):
        "Write dict to disk"
        if self.flag == "r":
            return
        filename = self.filename
        tempname = filename + ".tmp"
        fileobj = open(tempname, "wb")
        try:
            self.dump(fileobj)
        except Exception:
            os.remove(tempname)
            raise
        finally:
            fileobj.close()
        shutil.move(tempname, self.filename)  # atomic commit
        if self.mode is not None:
            os.chmod(self.filename, self.mode)

    def close(self):
        self.sync()

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()

    def dump(self, fileobj):
        fileobj.write(self.box.encrypt(pickle.dumps(dict(self))))

    def load(self, fileobj):
        fileobj.seek(0)
        obj = pickle.loads(self.box.decrypt(fileobj.read()))
        return self.update(obj)
