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

import sys
import os
import re
import subprocess
import locale
import email.message
import email.header
import email.charset
import io
import pwd
import shlex
import tempfile
import ALCLog
import ALChacks
from ALChacks import _

# TODO:
# newt-like frontend, or maybe some GUI bit
# keep track of tar/dpkg-deb errors like in pre-2.0

BREAK_APT_EXIT_CODE=10

def confirm_or_exit(config, frontend):
    if not config.confirm:
        return
    try:
        if not frontend.confirm():
            ALCLog.error(_('Aborting'))
            sys.exit(BREAK_APT_EXIT_CODE)
    except (KeyboardInterrupt, EOFError):
        sys.exit(BREAK_APT_EXIT_CODE)
    except Exception as ex:
        ALCLog.error(_("Confirmation failed: %s") % str(ex))
        sys.exit(1)

def mail_changes(config, changes, subject):
    ALCLog.info(_("Mailing %(address)s: %(subject)s") %
                  {'address': config.email_address,
                   'subject': subject})

    charset = email.charset.Charset('utf-8')
    charset.body_encoding = '8bit'
    charset.header_encoding = email.charset.QP
    message = email.message.Message()
    if config.email_format == 'html':
        changes = html(config).convert_to_html(subject, changes)
        message['Content-Type'] = 'text/html; charset=utf-8'
    message['Auto-Submitted'] = 'auto-generated'
    message['Subject'] = email.header.Header(subject, charset)
    message['To'] = config.email_address
    message.set_payload(changes, charset)

    try:
        subprocess.run(['/usr/sbin/sendmail', '-oi', '-t'], input=message.as_bytes(), check=True)
    except Exception as ex:
        ALCLog.warning(_("Failed to send mail to %(address)s: %(errmsg)s") %
                        {'address': config.email_address,
                         'errmsg': ex})

''' Check if the mail frontend is usable. When the second parameter is given
    print an appropriate error message '''
def can_send_emails(config, replacementFrontend = None):
    if not os.path.exists("/usr/sbin/sendmail"):
        if replacementFrontend:
            ALCLog.error(_("The mail frontend needs an installed 'sendmail', using %s")
                                % replacementFrontend)
        return False

    if not config.email_address:
        if replacementFrontend:
            ALCLog.error(_("The mail frontend needs an e-mail address to be configured, using %s")
                                % replacementFrontend)
        return False

    return True

''' Exception class to notify callers of make_frontend() that invalid frontend
    was given in the configuration'''
class EUnknownFrontend(Exception):
    pass

def _select_frontend(config, frontends):
    ''' Utility function used for testing purposes '''
    prompt = "\n" + _("Available apt-listchanges frontends:") + "\n" + \
             "".join(["  %d. %s\n"%(i+1,frontends[i]) for i in range(0, len(frontends))]) + \
             _("Choose a frontend by entering its number: ")

    for i in (1,2,3):
        try:
            response = ttyconfirm(config).ttyask(prompt)
            if not response:
                break
            return frontends[int(response)-1]
        except Exception as ex:
            ALCLog.error(_("Error: %s") % str(ex))

    ALCLog.info(_("Using default frontend: %s") % config.frontend)
    return config.frontend

def make_frontend(config, packages_count):
    frontends = { 'text' : text_frd,
                  'pager' : pager_frd,
                  'debconf': debconf_frd,
                  'mail' : mail_frd,
                  'browser' : browser_frd,
                  'xterm-pager' : xterm_pager_frd,
                  'xterm-browser' : xterm_browser_frd,
                  'gtk' : None, # handled below
                  'none' : None }

    if config.select_frontend: # For testing purposes
        name = _select_frontend(config, sorted(list(frontends.keys())))
    else:
        name = config.frontend

    if name == 'none':
        return None

    # If user does not want any messages force either the mail frontend
    # or no frontend at all if mail is not usable
    if config.quiet >= 2:
        if can_send_emails(config):
            name = 'mail'
        else:
            return None

    # If apt is in quiet (loggable) mode, we should make our output
    # loggable too unless the mail frontend is used (see #788059)
    elif config.quiet == 1:
        if name != 'mail' or not can_send_emails(config, 'text'):
            name = 'text'

    # Non-quiet mode
    else:
        if name == "mail" and not can_send_emails(config, 'pager'):
            name = 'pager'

        if name in ('gtk', 'xterm-pager', 'xterm-browser') and "DISPLAY" not in os.environ:
            name = name[6:] if name.startswith('xterm-') else 'pager'
            ALCLog.error(_("$DISPLAY is not set, falling back to %(frontend)s")
                               % {'frontend' : name})

        # TODO: it would probably be nice to have a frontends subdir and
        # import from that. that would mean a uniform mechanism for all
        # frontends (that would become small files inside
        if name == "gtk":
            try:
                gtk = __import__("AptListChangesGtk")
                frontends[name] = gtk.gtk_frd
            except ImportError as ex:
                if config.apt_mode and config.frontend_from_env:
                    # Most probably apt-listchanges was called from tool like synaptic
                    # Force text frontend without confirmations asthe the tool might
                    # appear to hang otherwise.
                    name = 'text'
                    config.confirm = False
                else:
                    name = 'pager'

                ALCLog.error(_("The gtk frontend needs a working python3-gi,\n"
                               "but it cannot be loaded. Falling back to %(frontend)s.\n"
                               "The error is: %(errmsg)s")
                                % {'frontend': name, 'errmsg': ex})

    config.frontend = name
    if name not in frontends:
        raise EUnknownFrontend
    return frontends[name](config, packages_count)

class base(object):
    def __init__(self, config, *args):
        super().__init__()
        self.config = config

    def _render(self, text):
        return text


class titled(base):
    def __init__(self, *args):
        super().__init__(*args)
        self.title = 'apt-listchanges output'

    def set_title(self, title):
        self.title = title

class frontend(titled):
    def __init__(self, config, packages_count):
        super().__init__(config, packages_count)
        self.packages_count = packages_count

    def update_progress(self, diff = 1):
        pass

    def progress_done(self):
        pass

    def display_output(self, text):
        pass

    def needs_tty_stdin(self):
        return False

    def confirm(self):
        return True


class debconf_frd(frontend):
    def display_output(self, text):
        import socket
        import debconf as dc
        if 'DEBIAN_FRONTEND' not in os.environ or os.environ['DEBIAN_FRONTEND'] != 'passthrough':
            return
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
        sock.connect(os.environ['DEBCONF_PIPE'])
        dcfd = sock.makefile()
        sock.close()
        db = dc.Debconf(read=dcfd, write=dcfd)
        tmp = tempfile.NamedTemporaryFile(prefix="apt-listchanges-tmp")
        os.fchmod(tmp.fileno(), 0o644)
        tmp.write(b'''Template: apt-listchanges/info
Type: title
Description: NEWS

Template: apt-listchanges/title
Type: title
Description: ${title}

Template: apt-listchanges/news
Type: note
Description: ${packages_count} packages\n''')
        for line in text.split('\n'):
            if line.strip():
                tmp.write('  ' + line + '\n')
            else:
                tmp.write(' .\n')
        tmp.flush()
        db.command('x_loadtemplatefile', tmp.name)
        tmp.close()
        db.info('apt-listchanges/info')
        db.subst('apt-listchanges/title', 'title', self.title)
        db.subst('apt-listchanges/news', 'packages_count', self.packages_count)
        db.settitle('apt-listchanges/title')
        db.fset('apt-listchanges/news', 'seen', 'false')
        db.input('high', 'apt-listchanges/news')
        db.go()
        dcfd.close()

class ttyconfirm(base):
    def ttyask(self, prompt):
        if sys.stdin.isatty() and sys.stdout.isatty():
            return input(prompt).rstrip()

        tty = open('/dev/tty', 'rb+', buffering=0)
        enc = ALChacks.system_encoding()
        tty.write(enc.to_bytes(prompt))
        tty.flush()
        return enc.from_bytes(tty.readline()).rstrip()

    def confirm(self):
        response = self.ttyask('apt-listchanges: ' + _('Do you want to continue? [Y/n] '))
        return response == '' or re.search(locale.nl_langinfo(locale.YESEXPR),
                                           response)
    def needs_tty_stdin(self):
        return self.config.confirm

class simpleprogress(base):
    def update_progress(self, diff = 1):
        if self.config.quiet > 1:
            return

        if not hasattr(self, 'message_printed'):
            self.message_printed = 1
            ALCLog.info(_("Reading changelogs") + "...")

    def progress_done(self):
        pass

class mail_frd(simpleprogress, frontend):
    pass

class prepend_title(titled):
    def _render(self, text):
        return self.title + '\n' + (len(self.title) * '-') + \
                '\n\n' + text

class text_frd(prepend_title, simpleprogress, ttyconfirm, frontend):
    def display_output(self, text):
        sys.stdout.write(ALChacks.system_encoding().as_string(self._render(text)))

class fancyprogress(base):
    def update_progress(self, diff = 1):
        if not diff:
            return
        if not hasattr(self, 'progress'):
            # First call
            self.progress = 0
            self.line_length = 0
        self.progress += diff
        line = _("Reading changelogs") + "... %d%%" % (self.progress * 100 / self.packages_count)
        self.line_length = len(line)
        sys.stdout.write(line + '\r')
        sys.stdout.flush()

    def progress_done(self):
        if hasattr(self, 'line_length'):
            sys.stdout.write(' ' * self.line_length + '\r')
            sys.stdout.write(_("Reading changelogs") + "... " + _("Done") + "\n")
            sys.stdout.flush()

class runcommand(base):
    def __init__(self, *args):
        super().__init__(*args)
        self.wait = True
        self.suffix = ''
        # Derived classes should set enc to system_encoding() or utf8_encoding() from ALChacks
        self.enc = None

    def display_output(self, text):
        # Note: the following fork() call is needed to have temporary file deleted
        # after the process created by Popen finishes.
        if not self.wait and os.fork() != 0:
            # We are the parent, return.
            return

        tmp = tempfile.NamedTemporaryFile(prefix="apt-listchanges-tmp", suffix=self.suffix, dir=self.get_tmpdir())
        tmp.write(self.enc.to_bytes(self._render(text)))
        tmp.flush()
        self.fchown_tmpfile(tmp.fileno())

        process = subprocess.Popen(self.get_command() + [tmp.name], preexec_fn=self.get_preexec_fn(), env=self.get_environ())
        status = process.wait()

        self._close_temp_file(tmp)

        if status != 0:
            raise OSError(_("Command %(cmd)s exited with status %(status)d")
                          % {'cmd': str(process.args), 'status': status})

        if not self.wait:
            # We are a child; exit
            sys.exit(0)

    def _close_temp_file(self, tmp):
        # Explicitly close the temporary file to ignore errors if the file
        # has been removed already, see bug#772663
        try:
            tmp.close()
        except FileNotFoundError:
            pass

    def get_command(self):
        return self.command

    # Interface functions for dropping root privileges
    def fchown_tmpfile(self, fileno):
        pass
    def get_tmpdir(self):
        return None
    def get_preexec_fn(self):
        return None
    def get_environ(self):
        return None

class runcommand_drop_privs(runcommand):
    def __init__(self, *args):
        super().__init__(*args)
        self._user_pw = self._find_user_pw()
        self._tmpdir = self._find_tmpdir()
        if self.config.debug and self._user_pw:
            ALCLog.debug(_("Found user: %(user)s, temporary directory: %(dir)s")
                    % {'user': self._user_pw.pw_name, 'dir': self._tmpdir})

    def fchown_tmpfile(self, fileno):
        if self._user_pw:
            os.fchown(fileno, self._user_pw.pw_uid, self._user_pw.pw_gid)

    def get_tmpdir(self):
        return self._tmpdir

    def get_preexec_fn(self):
        if not self._user_pw:
            return None
        def preexec():
            try:
                os.setgid(self._user_pw.pw_gid);
                os.setuid(self._user_pw.pw_uid);
            except Exception as ex:
                ALCLog.error(_("Error: %s") % str(ex))
        return preexec

    def get_environ(self):
        if not self._user_pw:
            return None
        newenv = os.environ
        newenv['HOME'] = self._user_pw.pw_dir
        newenv['SHELL'] = self._user_pw.pw_shell
        for envvar in ('USERNAME', 'USER', 'LOGNAME'):
            newenv[envvar] = self._user_pw.pw_name
        if self._tmpdir:
            for envvar in ('TMPDIR', 'TMP', 'TEMPDIR', 'TEMP'):
                newenv[envvar] = self._tmpdir
        return newenv

    def _find_user_pw(self):
        if os.getuid() != 0:
            return None

        pwdata = None
        for envvar in ('APT_LISTCHANGES_USER', 'SUDO_USER', 'USERNAME'):
            if envvar in os.environ:
                try:
                    user = os.environ[envvar]
                    pwdata = pwd.getpwnam(user) if not user.isdigit() else pwd.getpwuid(user)
                    break # check the first environment variable only
                except Exception as ex:
                    raise RuntimeError(_("Error getting user from variable '%(envvar)s': %(errmsg)s")
                                        % {'envvar': envvar, 'errmsg': str(ex)}) from ex

        if pwdata and pwdata.pw_uid:
            return pwdata

        ALCLog.warning(_("Cannot find suitable user to drop root privileges"))
        return None

    def _find_tmpdir(self):
        if not self._user_pw:
            return None
        tmpdir = tempfile.gettempdir()
        flags = os.R_OK | os.W_OK | os.X_OK
        os.setreuid(self._user_pw.pw_uid, 0)
        try:
            # check the default directory from $TMPDIR variable
            if os.access(tmpdir, flags):
                return tmpdir
            checked_tmpdirs = [tmpdir]
            # replace pam_tmpdir's directory /tmp/user/0 into e.g. /tmp/user/1000
            if tmpdir.endswith("/0"):
                tmpdir = tmpdir[0:-1] + str(self._user_pw.pw_uid)
                if os.access(tmpdir, flags):
                    return tmpdir
                checked_tmpdirs.append(tmpdir)
            # finally try hard-coded location
            if tmpdir != "/tmp":
                tmpdir="/tmp"
                if os.access(tmpdir, flags):
                    return tmpdir
                checked_tmpdirs.append(tmpdir)
            raise RuntimeError(_("None of the following directories is accessible"
                                 " by user %(user)s: %(dirs)s")
                                %{'user': self._user_pw.pw_name,
                                  'dirs': str(checked_tmpdirs)})
        finally:
            os.setuid(0)

class xterm(runcommand_drop_privs):
    def __init__(self, *args):
        super().__init__(*args)
        self.mode = os.P_NOWAIT
        self.wait = False
        self.xterm = shlex.split(self.config.get('xterm', 'x-terminal-emulator'))

    def get_command(self):
        return self.xterm + ['-T', self.title, '-e'] + self.command

    def needs_tty_stdin(self):
        return False


class pager_frd(runcommand, prepend_title, ttyconfirm, fancyprogress, frontend):
    def __init__(self, *args):
        super().__init__(*args)
        self._setup_less_variable()
        self.command = shlex.split(self.config.get('pager', 'sensible-pager'))
        self.suffix = '.txt'
        self.enc = ALChacks.system_encoding()

    def _setup_less_variable(self):
        prompt = "-P?e(%s)$" % _("press q to quit")
        less = os.environ.get('LESS', '')
        if not less:
            os.environ['LESS'] = prompt
            return

        # When the environment contains the LESS variable, try to disable
        # flags like -E (--QUIT-AT-EOF) and -F (--quit-if-one-screen) that
        # might cause to less program to quit before even user is able to
        # see the generated file.
        if 'E' in less or '--QUIT-A' in less:
            less += ' -+E'
        if 'F' in less or '--quit-i' in less:
            less += ' -+F'
        os.environ['LESS'] = less + ' ' + prompt

    def needs_tty_stdin(self):
        return True

class xterm_pager_frd(xterm, pager_frd):
    pass

class html(titled):
    # LP bug-closing format requires the colon after "LP", but many people
    # say "LP #123456" when talking informally about bugs.
    lp_bug_stanza_re = re.compile(r'(?:lp:?\s+\#\d+(?:,\s*\#\d+)*)', re.I)
    lp_bug_re        = re.compile('(?P<linktext>#(?P<bugnum>\d+))', re.I)
    lp_bug_fmt       = r'<a href="https://launchpad.net/bugs/\g<bugnum>">\g<linktext></a>'
    bug_stanza_re = re.compile(r'(?:closes:\s*(?:bug)?\#?\s?\d+(?:,\s*(?:bug)?\#?\s?\d+)*|(?<!">)#\d+)', re.I)
    bug_re        = re.compile('(?P<linktext>#?(?P<bugnum>\d+))', re.I)
    bug_fmt       = r'<a href="https://bugs.debian.org/\g<bugnum>">\g<linktext></a>'

    cve_re        = re.compile(r'\bC(VE|AN)-(19|20|21)\d\d-\d{4,7}\b')
    cve_fmt       = r'<a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=\g<0>">\g<0></a>'
    # regxlib.com
    email_re = re.compile(r'([a-zA-Z0-9_\+\-\.]+)@(([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)')
    email_fmt = r'<a href="mailto:\g<0>">\g<0></a>'
    url_re = re.compile(r'(ht|f)tps?\://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3}(:[a-zA-Z0-9]*)?/?([a-zA-Z0-9\-\._\?\,\'/\\\+&amp;%\$#\=~])*')
    url_fmt = r'<a href="\g<0>">\g<0></a>'

    def convert_to_html(self, title, text):
        self.set_title(title)
        return self._render(text)

    def _render(self, text):
        htmltext = io.StringIO()
        htmltext.write('''<html>
        <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
        <title>''')
        htmltext.write(self.title)
        htmltext.write('''</title>
        </head>

        <body>
        <pre>''')

        for line in text.split('\n'):
            line = line.encode('utf-8').replace(
                b'&', b'&amp;').replace(
                b'<', b'&lt;').replace(
                b'>', b'&gt;').decode('utf-8')
            line = self.url_re.sub(self.url_fmt, line)
            line = self.lp_bug_stanza_re.sub(lambda m: self.lp_bug_re.sub(self.lp_bug_fmt, m.group(0)), line)
            line = self.bug_stanza_re.sub(lambda m: self.bug_re.sub(self.bug_fmt, m.group(0)), line)
            line = self.cve_re.sub(self.cve_fmt, line)
            line = self.email_re.sub(self.email_fmt, line)
            htmltext.write(line + '\n')
        htmltext.write('</pre></body></html>')

        return htmltext.getvalue()

class browser_frd(html, runcommand_drop_privs, ttyconfirm, fancyprogress, frontend):
    def __init__(self, *args):
        super().__init__(*args)
        self.command = shlex.split(self.config.get('browser', 'sensible-browser'))
        self.suffix = '.html'
        self.enc = ALChacks.utf8_encoding()

    def needs_tty_stdin(self):
        return True


class xterm_browser_frd(xterm, browser_frd):
    pass
