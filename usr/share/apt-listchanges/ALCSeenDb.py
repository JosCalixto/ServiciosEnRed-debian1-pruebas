# vim:set fileencoding=utf-8 et ts=4 sts=4 sw=4:
#
#   apt-listchanges - Show changelog entries between the installed versions
#                     of a set of packages and the versions contained in
#                     corresponding .deb files
#
#   Copyright (C) 2000-2006  Matt Zimmerman  <mdz@debian.org>
#   Copyright (C) 2006       Pierre Habouzit <madcoder@debian.org>
#   Copyright (C) 2016       Robert Luberda  <robert@debian.org>
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public
#   License along with this program; if not, write to the Free
#   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston,
#   MA 02111-1307 USA
#

from dbm import ndbm
from ALChacks import _
import os
import shutil

import sys

class DbError(Exception):
    pass

class seendb_dummy(object):
    '''Interface for seen database.
       Also used when path to the database is not configured'''
    def __contains__(self, srcpackage):
        return False

    def __getitem__(self, srcpackage):
        pass

    def __setitem__(self, srcpackage, version):
        pass
	
    def close_db(self):
        pass

    def apply_changes(self):
        pass

    def dump(self):
        raise DbError(_("Path to the seen database is unknown.\n"
                        "Please either specify it with --save-seen option\n"
                        "or pass --profile=apt to have it read from the configuration file."))

class seendb(seendb_dummy):
    '''Class to manage the seen database'''
    def __init__(self, path, readOnly = False):
        super().__init__()

        self._extension = '.db'
        if path[-3:] != self._extension:
            raise DbError(_("Database %(db)s does not end with %(ext)s")
                            % {'db': path, 'ext': self._extension})

        self._dbpath   = path[:-3] # strip the .db suffix
        try:
            mode = 'r' if readOnly else 'c'
            self._seen = ndbm.open(self._dbpath, mode, 0o644)
            'foo%0' in self._seen
        except Exception as ex:
            raise DbError(_("Database %(db)s failed to load: %(errmsg)s")
                            % {'db': path, 'errmsg': str(ex)}) from ex

        # Will replace seen after changes have actually been seen
        self._seen_new = {}

    def __contains__(self, srcpackage):
        return srcpackage in self._seen

    def __getitem__(self, srcpackage):
        return self._seen[srcpackage].decode()

    def __setitem__(self, srcpackage, version):
        if self._seen.get(srcpackage, b'').decode() != version:
            # Note: updating _seen_new, not _seen
            self._seen_new[srcpackage] = version
	
    def close_db(self):
        self._seen.close()
        self._seen = None

    def apply_changes(self):
        if not self._seen_new:
            # Nothing to update
            return

        def mk(arg):
            return self._dbpath + arg + self._extension
        old, cur, new = (mk('-old'), mk(''), mk('-new'))

        # For reliability and to have backup of the database,
        # it is updated in the following steps:
        # 1. copy current version to new
        if os.path.isfile(cur):
            shutil.copy(cur, new)

        # 2. apply the changes to new
        seen = ndbm.open(self._dbpath + '-new', 'c', 0o644)
        for (key, value) in self._seen_new.items():
            seen[key] = value
        seen.close()

        # 3. save current as old, and rename new to current
        if os.path.isfile(old):
            os.unlink(old)
        if os.path.isfile(cur):
            os.link(cur, old)
        os.rename(new, cur)

    def dump(self):
        for key in sorted(self._seen.keys()):
            value = self._seen[key]
            print("%s %s" % (key.decode(), value.decode()))


def make_seen_db(config, readOnly = False):
    if config.save_seen:
        return seendb(config.save_seen, readOnly)
    return seendb_dummy()
