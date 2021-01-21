# vim:set fileencoding=utf-8 et ts=4 sts=4 sw=4:
#
#   apt-listchanges - Show changelog entries between the installed versions
#                     of a set of packages and the versions contained in
#                     corresponding .deb files
#
#   Copyright (C) 2007       Pierre Habouzit <madcoder@debian.org>
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

import gettext
import locale
import os
import sys

try:
    locale.setlocale(locale.LC_ALL, '')
except locale.Error:
    sys.stderr.write("apt-listchanges: Can't set locale; make sure $LC_* and $LANG are correct!\n")
    os.environ['LC_ALL'] = 'C'
    locale.setlocale(locale.LC_ALL, 'C')

# set the i18n dirs
gettext.bindtextdomain("apt-listchanges", "/usr/share/locale")
gettext.textdomain("apt-listchanges")

def _(x):
    try:
        return gettext.gettext(x)
    except:
        return x


# Utility classes for encoding conversions
class _base_encoding(object):
    def __init__(self, encoding):
        self._encoding = encoding;

    def get_encoding(self):
        return self._encoding

    def to_bytes(self, text):
        return text.encode(self._encoding, 'replace')

    def from_bytes(self, bintext):
        return bintext.decode(self._encoding, 'replace')

    def as_string(self, text):
        if self._encoding == 'utf-8':
            return text
        return self.from_bytes(self.to_bytes(text))

class utf8_encoding(_base_encoding):
    def __init__(self):
        _base_encoding.__init__(self, 'utf-8')

class system_encoding(_base_encoding):
    _sysencoding = locale.getpreferredencoding(False).lower()
    def __init__(self):
        _base_encoding.__init__(self, self._sysencoding)


# forcibly export _
__all__ = ['_']
