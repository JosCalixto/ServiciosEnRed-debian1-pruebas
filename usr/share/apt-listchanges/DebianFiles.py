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

import re
import sys, os
import tempfile
import gzip
import errno
import glob
import shutil
import shlex
import signal
import subprocess

import apt_pkg
import ALCLog
from ALChacks import _
from functools import reduce

# TODO:
# indexed lookups by package at least, maybe by arbitrary field

def _numeric_urgency(u):
    urgency_map = { 'critical'  : 1,
                    'emergency' : 1,
                    'high'      : 2,
                    'medium'    : 3,
                    'low'       : 4 }

    return urgency_map.get(u.lower(), 99)


class ControlStanza:
    source_version_re = re.compile('^\S+ \((?P<version>.*)\).*')
    fields_to_read = [ 'Package', 'Source', 'Version', 'Architecture', 'Status' ]

    def __init__(self, s):
        field = None

        for line in s.split('\n'):
            if not line:
                break
            if line[0] in (' ', '\t'):
                if field:
                    setattr(self, field, getattr(self, field) + '\n' + line)
            else:
                field, value = line.split(':', 1)
                if field in self.fields_to_read:
                    setattr(self, field, value.lstrip())
                else:
                    field = None


    def source(self):
        return getattr(self, 'Source', self.Package).split(' ')[0]

    def installed(self):
        return hasattr(self, 'Status') and self.Status.split(' ')[2] == 'installed'

    def version(self):
        """
        This function returns the version of the package. One would like it to
        be the "binary" version, though we have the tough case of source
        package whose binary packages versioning scheme is different from the
        source one (see OOo, linux-source, ...).

        This code does the following, if the Source field is set with a
        specified version, then we use the binary version if and only if the
        source version is a prefix. We must do that because of binNMUs.
        """
        v = self.Version
        if hasattr(self, 'Source'):
            match = self.source_version_re.match(self.Source)
            if match:
                sv = match.group('version')
                if not v.startswith(sv):
                    return sv
        return v


class ControlParser:
    def __init__(self):
        self.stanzas = []
        self.index = {}

    def makeindex(self, field):
        self.index[field] = {}
        for stanza in self.stanzas:
            self.index[field][getattr(stanza, field)] = stanza

    def readfile(self, file):
        try:
            self.stanzas += [ControlStanza(x) for x in open(file, 'r', encoding='utf-8', errors='replace').read().split('\n\n') if x]
        except Exception as ex:
            raise RuntimeError(_("Error processing '%(what)s': %(errmsg)s") %
                                {'what': file, 'errmsg': str(ex)}) from ex

    def readdeb(self, deb):
        try:
            command = ['dpkg-deb', '-f', deb] + ControlStanza.fields_to_read
            output = subprocess.check_output(command)
            self.stanzas.append(ControlStanza(output.decode('utf-8', 'replace')))
        except Exception as ex:
            raise RuntimeError(_("Error processing '%(what)s': %(errmsg)s") %
                                {'what': file, 'errmsg': str(ex)}) from ex

    def find(self, field, value):
        if field in self.index:
            if value in self.index[field]:
                return self.index[field][value]
            else:
                return None
        else:
            for stanza in self.stanzas:
                if hasattr(stanza, field) and getattr(stanza, field) == value:
                    return stanza
        return None

class ChangelogParser:
    _changelog_header = re.compile('^\S+ \((?P<version>.*)\) .*;.*urgency=(?P<urgency>\w+).*')
    _changelog_header_ancient = re.compile('^(\S+ \(?\d.*\)|Old Changelog:|Changes|ChangeLog begins|Mon|Tue|Wed|Thu|Fri|Sat|Sun).*')
    _changelog_header_emacs = re.compile('(;;\s*)?Local\s+variables.*', re.IGNORECASE)

    def __init__(self):
        self._entry = ''
        self._entries = []

    def parse(self, fd, since_version):
        '''Parse changelog or news from the given file descriptor.
        If since_version is specified, only return entries later
        than the specified version.'''
        urgency = _numeric_urgency('low')
        is_debian_changelog = False
        ancient = False

        for line in fd.readlines():
            line = line.decode('utf-8', 'replace')

            if line.startswith(' ') or line == '\n':
                self._add_line(line)

            elif line.startswith('#'):
                continue

            else:
                match = self._changelog_header.match(line) if not ancient else None
                if match:
                    is_debian_changelog = True
                    if since_version and apt_pkg.version_compare(match.group('version'),
                                                                 since_version) <= 0:
                        break
                    urgency = min(_numeric_urgency(match.group('urgency')),
                                  urgency)
                    self._save_entry(line)

                elif self._changelog_header_ancient.match(line):
                    if not is_debian_changelog: # probably upstream changelog in GNU format
                        break
                    ancient = True
                    self._save_entry(line)

                elif self._changelog_header_emacs.match(line):
                    break

                elif is_debian_changelog:
                    self._add_line(line)

                else:
                    break

        if not is_debian_changelog:
            return None, None

        self._save_entry(None)

        return self._entries, urgency

    def _add_line(self, line):
        self._entry += line

    def _save_entry(self, new_entry_header):
        self._entry = self._entry.strip()
        if self._entry != '':
            self._entries += [ self._entry + '\n' ]
        self._entry = new_entry_header

class Package:
    def __init__(self, path):
        self.path = path

        parser = ControlParser()
        parser.readdeb(self.path)
        pkgdata = parser.stanzas[0]

        self.binary  = pkgdata.Package
        self.source  = pkgdata.source()
        self.Version = pkgdata.version()
        self.arch = pkgdata.Architecture

    def extract_changes(self, which, since_version, reverse):
        '''Extract changelog and binnmu entries, news or both from the package.

        Unpacks changelog or news files from the binary package, and parses them.
        If since_version is specified, only return entries later than the specified version.
        Returns a tuple of sequences of Changes objects.'''

        news_filenames = self._changelog_variations('NEWS.Debian')
        changelog_filenames = self._changelog_variations('changelog.Debian')
        changelog_filenames_binnmu = self._changelog_variations('changelog.Debian.' + self.arch)
        changelog_filenames_native = self._changelog_variations('changelog')

        filenames = []
        if which == 'both' or which == 'news':
            filenames.extend(news_filenames)
        if which == 'both' or which == 'changelogs':
            filenames.extend(changelog_filenames)
            filenames.extend(changelog_filenames_binnmu)
            filenames.extend(changelog_filenames_native)

        tempdir = self._extract_contents(filenames)
        try:

            find_first = lambda acc, fname: acc or self._read_changelog(os.path.join(tempdir, fname),
                                                                        since_version, reverse)

            news       = reduce(find_first, news_filenames, None)
            changelog  = reduce(find_first, changelog_filenames + changelog_filenames_native, None)
            binnmu     = reduce(find_first, changelog_filenames_binnmu, None)

        finally:
            shutil.rmtree(tempdir, 1)

        return (news, changelog, binnmu)

    def extract_changes_via_apt(self, since_version, reverse):
        '''Run apt-get changelog and parse the downloaded changelog.

        Retrieve changelog using the "apt-get changelog" command, and parse it.
        If since_version is specified, only return entries later than the specified version.
        Returns a single sequence of Changes objects or None on downloading or parsing failure.'''

        # Retrieve changelog file and save it in a temporary directory
        tempdir = tempfile.mkdtemp(prefix='apt-listchanges')
        changelog_file = os.path.join(tempdir, self.binary + '.changelog')
        changelog_fd = open(changelog_file, 'w')

        try:

            command = ['apt-get', '-qq', 'changelog', '%s=%s' % (self.binary, self.Version)]
            ALCLog.debug(_("Calling %(cmd)s to retrieve changelog") % {'cmd': str(command)})
            subprocess.run(command, stdout=changelog_fd, stderr=subprocess.PIPE, timeout=120, check=True)

        except subprocess.CalledProcessError as ex:
            ALCLog.error(_('Unable to retrieve changelog for package %(pkg)s; '
                           + "'apt-get changelog' failed with: %(errmsg)s")
                           % {'pkg': self.binary,
                              'errmsg': ex.stderr.decode('utf-8', 'replace') if ex.stderr else str(ex)})

        except Exception as ex:
            ALCLog.error(_('Unable to retrieve changelog for package %(pkg)s; '
                          + "could not run 'apt-get changelog': %(errmsg)s")
                           % {'pkg': self.binary,
                              'errmsg': str(ex)})

        else:
            return self._read_changelog(changelog_file, since_version, reverse)

        finally:
            changelog_fd.close()
            shutil.rmtree(tempdir, 1)

        return None


    def _extract_contents(self, filenames):
        tempdir = tempfile.mkdtemp(prefix='apt-listchanges')

        extract_command = 'dpkg-deb --fsys-tarfile %s | tar xf - --wildcards -C %s %s 2>/dev/null' % (
            shlex.quote(self.path), shlex.quote(tempdir),
            ' '.join([shlex.quote(x) for x in filenames])
        )

        # tar exits unsuccessfully if _any_ of the files we wanted
        # were not available, so we can't do much with its status
        status = os.system(extract_command)

        if os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGINT:
            shutil.rmtree(tempdir, 1)
            raise KeyboardInterrupt

        return tempdir

    def _open_changelog_file(self, filename):
        filenames = glob.glob(filename)

        for filename in filenames:
            try:
                if os.path.isdir(filename):
                    ALCLog.error(_("Ignoring `%s' (seems to be a directory!)") % filename)
                elif filename.endswith('.gz'):
                    return gzip.GzipFile(filename)
                else:
                    return open(filename, 'rb')
                break
            except IOError as e:
                if e.errno != errno.ENOENT and e.errno != errno.ELOOP:
                    raise
        return None

    def _read_changelog(self, filename, since_version, reverse=False):
        fd = self._open_changelog_file(filename)
        if not fd:
            return None

        entries, urgency = ChangelogParser().parse(fd, since_version)

        if urgency is None:
            return None # not a Debian changelog file

        if not entries:
            # Valid Debian changelog, but all entries filtered out due
            # to --since-version. Return empty string to prevent the caller
            # from searching for another Debian changelog file.
            return Changes(self.source, "", urgency)

        if reverse:
            entries.reverse()

        changes = "\n".join(entries) + "\n"

        return Changes(self.source, changes, urgency)

    def _changelog_variations(self, filename):
        formats = ['./usr/share/doc/*/%s.gz',
                   './usr/share/doc/*/%s']
        return [x % filename for x in formats]

class Changes:
    def __init__(self, package, changes, urgency):
        self.package = package
        self.changes = changes
        self.urgency = urgency

    def merge_binnmu(self, other, reverse = False):
        assert self.package == other.package
        self.urgency = min(self.urgency, other.urgency)
        # Assumption: binnmu has greater version than regular changelog
        if reverse:
            self.changes = self.changes + other.changes
        else:
            self.changes = other.changes + self.changes

__all__ = [ 'ControlParser', 'Package' ]
