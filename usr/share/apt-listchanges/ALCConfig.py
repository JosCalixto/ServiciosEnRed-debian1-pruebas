# vim:set fileencoding=utf-8 et ts=4 sts=4 sw=4:
#
#   apt-listchanges - Show changelog entries between the installed versions
#                     of a set of packages and the versions contained in
#                     corresponding .deb files
#
#   Copyright (C) 2000-2006  Matt Zimmerman  <mdz@debian.org>
#   Copyright (C) 2006       Pierre Habouzit <madcoder@debian.org>
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

import configparser
import getopt
import sys, os
import re

import ALCLog
from ALChacks import *

class ALCConfig:
    def __init__(self):
        ### Command line only options
        self.apt_mode = False   # "--apt" option
        self.dump_seen = False
        self.profile = None

        ### Options that can be set in the config file
        self.frontend = 'pager'
        self.email_address = None
        self.email_format = 'text'
        self.verbose = False
        self.show_all = False
        self.confirm = False
        self.headers = False
        self.debug = False
        self.save_seen = None
        self.which = 'both'
        self.since = None
        self.reverse = False
        self.no_network = False
        self.select_frontend = False
        self.ignore_apt_assume = False
        self.ignore_debian_frontend = False

        ### Internal options for managing the config file options
        # - options that can be also used for command line parameters
        #   (after replacing '_' with '-', and adding trailing '=' if needed)
        self._bool_opts = ['confirm', 'debug', 'show_all', 'headers', 'verbose', 'reverse',
                           'dump_seen', 'select_frontend', 'no_network',
                           'ignore_apt_assume', 'ignore_debian_frontend']
        self._value_opts = ['frontend', 'email_address', 'email_format', 'save_seen', 'since', 'which']
        # - options that can be given only in the config file
        self._cfgfile_only_opts = ['browser', 'pager', 'xterm']

        ### Other options
        self.quiet = 0
        self.frontend_from_env = False
        self._allowed_email_formats = ('text', 'html')
        self._allowed_which = ('both', 'news', 'changelogs')

    def read(self, file):
        self.parser = configparser.ConfigParser()
        self.parser.read(file)

    def expose(self):
        if self.parser.has_section(self.profile):
            for option in self.parser.options(self.profile):
                value = None
                if self.parser.has_option(self.profile, option):
                    if option in self._bool_opts:
                        value = self.parser.getboolean(self.profile, option)
                    elif option in self._value_opts  or option in self._cfgfile_only_opts:
                        value = self.parser.get(self.profile, option)
                    else:
                        ALCLog.warning(_("Unknown configuration file option: %s") % option)
                        continue
                setattr(self, option, value)

    def get(self, option, defvalue=None):
        return getattr(self, option, defvalue)

    def usage(self, exitcode):
        if exitcode == 0:
            fh = sys.stdout
        else:
            fh = sys.stderr

        fh.write(_("Usage: apt-listchanges [options] {--apt | filename.deb ...}\n"))
        sys.exit(exitcode)

    def _check_allowed(self, arg, opt, allowed):
        if arg in allowed:
            return arg
        ALCLog.error((_('Unknown argument %(arg)s for option %(opt)s.  Allowed are: %(allowed)s.') %
                          {'arg': arg, 'opt': opt, 'allowed': ', '.join(allowed)}))
        sys.exit(1)

    def _check_debs(self, debs):
        if self.apt_mode or self.dump_seen:
            return
        if (debs == None or len(debs) == 0):
            self.usage(1);
        for deb in debs:
            ext = os.path.splitext(deb)[1]
            if ext != ".deb":
                ALCLog.error(_("%(deb)s does not have '.deb' extension") % {'deb': deb})
                sys.exit(1)
            if not os.path.isfile(deb):
                ALCLog.error(_('%(deb)s does not exist or is not a file') % {'deb': deb})
                sys.exit(1)
            if not os.access(deb, os.R_OK):
                ALCLog.error(_('%(deb)s is not readable') % {'deb' : deb})
                sys.exit(1)

    def getopt(self, argv):
        try:
            (optlist, args) = getopt.getopt(argv[1:], 'vf:s:cah', [
                # command line only
                "apt", "profile=", "help",
                # deprecated options for backward compatibility
                "all", "save_seen=" ]
                # boolean options
                + [ x.replace('_', '-') for x in  self._bool_opts ]
                # with value options
                + [ x.replace('_', '-')+'=' for x in self._value_opts ]
            )
        except getopt.GetoptError as err:
            ALCLog.error(str(err))
            sys.exit(1)

        # Determine mode and profile before processing other options
        for opt, arg in optlist:
            if opt == '--profile':
                self.profile = arg
            elif opt == '--apt':
                self.apt_mode = True

        # Provide a default profile if none has been specified
        if self.profile is None:
            if self.apt_mode:
                self.profile = 'apt'
            else:
                self.profile = 'cmdline'

        # Expose defaults from config file
        self.expose()

        # Environment variables override config file
        if 'APT_LISTCHANGES_FRONTEND' in os.environ:
            self.frontend = os.getenv('APT_LISTCHANGES_FRONTEND')
            self.frontend_from_env = True
            # Prefer APT_LISTCHANGES_FRONTEND over DEBIAN_FRONTEND
            self.ignore_debian_frontend = True

        (since, show_all) = (None, False)

        # Command-line options override environment and config file
        for opt, arg in optlist:
            if opt == '--help':
                self.usage(0)
            elif opt in ('-v', '--verbose'):
                self.verbose = True
            elif opt in ('-f', '--frontend'):
                self.frontend = arg
            elif opt == '--email-address':
                self.email_address = arg
            elif opt == '--email-format':
                self.email_format = self._check_allowed(arg, opt, self._allowed_email_formats)
            elif opt in ('-c', '--confirm'):
                self.confirm = True
            elif opt in ('--since'):
                since = arg
            elif opt in ('-a', '--show-all', '--all'):
                show_all = True
            elif opt in ('-h', '--headers'):
                self.headers = True
            elif opt in ('--save-seen', '--save_seen'):
                self.save_seen = arg
            elif opt == '--dump-seen':
                self.dump_seen = True
            elif opt == '--which':
                self.which = self._check_allowed(arg, opt, self._allowed_which)
            elif opt == '--debug':
                self.debug = True
            elif opt == '--reverse':
                self.reverse = True
            elif opt in ('-n', '--no-network'):
                self.no_network = True
            elif opt == '--select-frontend':
                self.select_frontend = True
            elif opt == '--ignore-apt-assume':
                self.ignore_apt_assume = True
            elif opt == '--ignore-debian-frontend':
                self.ignore_debian_frontend = True

        if self.email_address == 'none':
            self.email_address = None
        if self.save_seen == 'none':
            self.save_seen = None

        if ((self.since is not None and self.show_all)
           or (since is not None and show_all)):
                ALCLog.error(_('--since=<version> and --show-all are mutually exclusive'))
                sys.exit(1)
        elif since is not None or show_all:
            self.since = since
            self.show_all = show_all

        if self.since is not None:
            if len(args) != 1:
                ALCLog.error(_('--since=<version> expects a path to exactly one .deb archive'))
                sys.exit(1)
            self.save_seen = None

        if (self.apt_mode and not self.ignore_debian_frontend and
              os.getenv('DEBIAN_FRONTEND', '') == 'noninteractive'):
            # Force non-interactive usage
            self.quiet = 1
            self.confirm = False

        self._check_debs(args)

        return args

__all__ = [ 'ALCConfig' ]
