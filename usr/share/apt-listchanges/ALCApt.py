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

import os
import sys

import ALCConfig
import ALCLog
from ALChacks import _

def _parse_apt_bool(value):
    # Based on StringToBool() from apt-pkg/contrib/strutl.cc in apt source
    # and should return same result as StringToBool(value, false)
    return value.lower() in [ '1', 'yes', 'true', 'with', 'on', 'enable' ]

def _parse_apt_int(value):
    # This function should match Configuration::FindI() from apt's
    # apt-pkg/contrib/configuration.cc, except for values like '1something'
    try:
        return int(value)
    except:
        return 0

class AptPipelineError(Exception):
    pass

class AptPipeline(object):
    def __init__(self, config):
        super().__init__()
        self._config = config

    def read(self):
        fd = self._open_apt_fd()

        if self._config.debug:
            ALCLog.debug(_("APT pipeline messages:"))

        self._read_version(fd)
        self._read_options(fd)
        debs = self._read_packages(fd)

        if self._config.debug:
            ALCLog.debug(_("Packages list:"))
            for d in debs:
                ALCLog.debug("\t%s" % d)
            ALCLog.debug("")
        return debs

    def _open_apt_fd(self):
        if not 'APT_HOOK_INFO_FD' in os.environ:
            raise AptPipelineError(_("APT_HOOK_INFO_FD environment variable is not defined\n"
                    "(is Dpkg::Tools::Options::/usr/bin/apt-listchanges::InfoFD set to 20?)"))

        try:
            apt_hook_info_fd_val = int(os.environ['APT_HOOK_INFO_FD'])
        except Exception as ex:
            raise AptPipelineError(_("Invalid (non-numeric) value of APT_HOOK_INFO_FD"
                                     " environment variable")) from ex
        if self._config.debug:
            ALCLog.debug(_("Will read apt pipeline messages from file descriptor %d") % apt_hook_info_fd_val)

        if apt_hook_info_fd_val == 0: # TODO: remove this backward compatibility code in Debian 10 (Buster)
            ALCLog.warning(_("Incorrect value (0) of APT_HOOK_INFO_FD environment variable.\n"
                             "If the warning persists after restart of the package manager (e.g. aptitude),\n"
                             "please check if the /etc/apt/apt.conf.d/20listchanges file was properly updated."))

        elif apt_hook_info_fd_val < 3:
            raise AptPipelineError(_("APT_HOOK_INFO_FD environment variable is incorrectly defined\n"
                    "(Dpkg::Tools::Options::/usr/bin/apt-listchanges::InfoFD should be greater than 2)."))

        try:
            return os.fdopen(apt_hook_info_fd_val, 'rt')
        except Exception as ex:
            raise AptPipelineError(_("Cannot read from file descriptor %(fd)d: %(errmsg)s")
                                  % {'fd': apt_hook_info_fd_val, 'errmsg': str(ex) }) from ex

    def _read_version(self, fd):
        version = fd.readline().rstrip()
        if version != "VERSION 2":
            raise AptPipelineError(_("Wrong or missing VERSION from apt pipeline\n"
                "(is Dpkg::Tools::Options::/usr/bin/apt-listchanges::Version set to 2?)"))
        if self._config.debug:
            ALCLog.debug("\t%s" % version)

    def _read_options(self, fd):
        while True:
            line = fd.readline().rstrip()
            if self._config.debug:
                ALCLog.debug("\t%s" % line)
            if not line:
                return

            if (not self._config.ignore_apt_assume and
                  line.startswith('APT::Get::Assume-Yes=') and
                  _parse_apt_bool(line[len('APT::Get::Assume-Yes='):]) ):
                self._config.confirm = False
                # Set self._config.quiet as well to force non-interactive frontend
                self._config.quiet = max(1, self._config.quiet)
            elif line.startswith('quiet='):
                self._config.quiet = max(_parse_apt_int(line[len('quiet='):]), self._config.quiet)

    def _read_packages(self, fd):
        filenames = {}
        toconfig = []
        toremove = []
        hasupgrade = False

        for pkgline in fd.readlines():
            pkgline = pkgline.rstrip()
            if self._config.debug:
                ALCLog.debug("\t%s" % pkgline)
            if not pkgline:
                break

            (pkgname, oldversion, compare, newversion, filename) = pkgline.split(None, 4)
            if compare != '<': # ignore downgrades or re-installations
                continue

            if filename == '**REMOVE**' or filename == '**ERROR**':
                toremove.append(pkgname)
                continue

            # New installs (oldversion equal to '-') are not ignored to support
            # a case when changelog is moved from one package to a dependent
            # package built from the same source (see p7zip-full 15.09+dfsg-3).
            if oldversion != '-':
                hasupgrade = True

            if filename == '**CONFIGURE**':
                toconfig.append(pkgname)
            else:
                filenames[pkgname] = filename

        # Quit early if no package has been upgraded (e.g. only new installs or removals)
        if not hasupgrade:
            return []

        # Sort by configuration order.  THIS IS IMPORTANT.  Sometimes, a
        # situation exists where package X contains changelog.gz (upstream
        # changelog) and depends on package Y which contains
        # changelog.Debian.gz (Debian changelog).  Until we have a more
        # reliable method for determining whether a package is Debian
        # native, this allows things to work, since Y will always be
        # configured first.

        # apt doesn't explicitly configure everything anymore, so sort
        # the things to be configured first, and then do everything else
        # in alphabetical order.  Also, drop from the list everything
        # that's to be removed.
        for pkg in toremove:
            if pkg in filenames:
                del filenames[pkg]

        ordered_filenames = []
        for pkg in toconfig:
            if pkg in filenames:
                ordered_filenames.append(filenames[pkg])
                del filenames[pkg]

        ordered_filenames.extend(sorted(filenames.values()))
        return ordered_filenames
