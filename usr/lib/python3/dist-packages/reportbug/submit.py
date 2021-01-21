# reportbug_submit module - email and GnuPG functions
#   Written by Chris Lawrence <lawrencc@debian.org>
#   Copyright (C) 1999-2006 Chris Lawrence
#   Copyright (C) 2008-2019 Sandro Tosi <morph@debian.org>
#
# This program is freely distributable per the following license:
#
#  Permission to use, copy, modify, and distribute this software and its
#  documentation for any purpose and without fee is hereby granted,
#  provided that the above copyright notice appears in all copies and that
#  both that copyright notice and this permission notice appear in
#  supporting documentation.
#
#  I DISCLAIM ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL I
#  BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY
#  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
#  WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
#  ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
#  SOFTWARE.

import sys
import os
import re
import shlex
from subprocess import Popen, STDOUT, PIPE
import email
import smtplib
import socket
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.audio import MIMEAudio
from email.mime.image import MIMEImage
from email.mime.base import MIMEBase
from email.mime.message import MIMEMessage
import mimetypes

from .__init__ import VERSION, VERSION_NUMBER
from .tempfiles import TempFile, open_write_safe, tempfile_prefix
from .exceptions import (
    NoMessage,
)
from .ui import text_ui as ui
from .utils import get_email_addr
import errno

quietly = False

ascii_range = ''.join([chr(ai) for ai in range(32, 127)])
notascii = re.compile(r'[^' + re.escape(ascii_range) + ']')
notascii2 = re.compile(r'[^' + re.escape(ascii_range) + r'\s]')


# Cheat for now.
# ewrite() may put stuff on the status bar or in message boxes depending on UI
def ewrite(*args):
    return quietly or ui.log_message(*args)


def sign_message(body, fromaddr, package='x', pgp_addr=None, sign='gpg', draftpath=None):
    '''Sign message with pgp key.'''
    ''' Return: a signed body.
        On failure, return None.
        kw need to have the following keys
    '''
    if not pgp_addr:
        pgp_addr = get_email_addr(fromaddr)[1]

    # Make the unsigned file first
    (unsigned, file1) = TempFile(prefix=tempfile_prefix(package, 'unsigned'), dir=draftpath)
    unsigned.write(body)
    unsigned.close()

    # Now make the signed file
    (signed, file2) = TempFile(prefix=tempfile_prefix(package, 'signed'), dir=draftpath)
    signed.close()

    if sign == 'gpg':
        os.unlink(file2)
        if 'GPG_AGENT_INFO' not in os.environ:
            signcmd = "gpg --local-user '%s' --clearsign " % pgp_addr
        else:
            signcmd = "gpg --local-user '%s' --use-agent --clearsign " % pgp_addr
        signcmd += '--output ' + shlex.quote(file2) + ' ' + shlex.quote(file1)
    else:
        signcmd = "pgp -u '%s' -fast" % pgp_addr
        signcmd += '<' + shlex.quote(file1) + ' >' + shlex.quote(file2)

    try:
        os.system(signcmd)
        with open(file2, 'r', errors='backslashreplace') as x:
            signedbody = x.read()

        if os.path.exists(file1):
            os.unlink(file1)
        if os.path.exists(file2):
            os.unlink(file2)

        if not signedbody:
            raise NoMessage
        body = signedbody
    except (NoMessage, IOError, OSError):
        fh, tmpfile2 = TempFile(prefix=tempfile_prefix(package), dir=draftpath)
        fh.write(body)
        fh.close()
        ewrite('gpg/pgp failed; input file in %s\n', tmpfile2)
        body = None
    return body

def _MIMEText_wrapper(text):
    msg = MIMEText(text)
    # Too long lines need to be encoded (see RFC2822), but MIMEText does
    # not yet handle this for us.
    # Since utf-8 will already be base64-encoded at this point, we only
    # need to deal with the us-ascii case.
    if msg.get_content_charset() == 'us-ascii' and \
            max(len(l) for l in text.splitlines()) > 980:
        email.encoders.encode_quopri(msg)
        # due to a bug in the email library, the result now has two CTE
        # headers, only one of which is correct. Delete both and set the
        # correct value.
        del msg['Content-Transfer-Encoding']
        msg['Content-Transfer-Encoding'] = 'quoted-printable'
    return msg

def mime_attach(body, attachments, charset, body_charset=None):
    mimetypes.init()

    message = MIMEMultipart('mixed')
    bodypart = _MIMEText_wrapper(body)
    bodypart.add_header('Content-Disposition', 'inline')
    message.preamble = 'This is a multi-part MIME message sent by reportbug.\n\n'
    message.epilogue = ''
    message.attach(bodypart)
    failed = False
    for attachment in attachments:
        try:
            fp = open(attachment)
            fp.close()
        except EnvironmentError as x:
            ewrite("Warning: opening '%s' failed: %s.\n", attachment,
                   x.strerror)
            failed = True
            continue
        ctype = None
        cset = charset
        info = Popen(['file', '--mime', '--brief', '--dereference', attachment],
                     stdout=PIPE, stderr=STDOUT).communicate()[0].decode('ascii')
        if info:
            match = re.match(r'([^;, ]*)(,[^;]+)?(?:; )?(.*)', info)
            if match:
                ctype, junk, extras = match.groups()
                match = re.search(r'charset=([^,]+|"[^,"]+")', extras)
                if match:
                    cset = match.group(1)
                # If we didn't get a real MIME type, fall back
                if '/' not in ctype:
                    ctype = None
        # If file doesn't work, try to guess based on the extension
        if not ctype:
            ctype, encoding = mimetypes.guess_type(
                attachment, strict=False)
        if not ctype:
            ctype = 'application/octet-stream'

        maintype, subtype = ctype.split('/', 1)
        if maintype == 'text':
            try:
                with open(attachment, 'rU') as fp:
                    part = _MIMEText_wrapper(fp.read())
            except UnicodeDecodeError:
                fp = open(attachment, 'rb')
                part = MIMEBase(maintype, subtype)
                part.set_payload(fp.read())
                fp.close()
                email.encoders.encode_base64(part)
        elif maintype == 'message':
            fp = open(attachment, 'rb')
            part = MIMEMessage(email.message_from_file(fp),
                               _subtype=subtype)
            fp.close()
        elif maintype == 'image':
            fp = open(attachment, 'rb')
            part = MIMEImage(fp.read(), _subtype=subtype)
            fp.close()
        elif maintype == 'audio':
            fp = open(attachment, 'rb')
            part = MIMEAudio(fp.read(), _subtype=subtype)
            fp.close()
        else:
            fp = open(attachment, 'rb')
            part = MIMEBase(maintype, subtype)
            part.set_payload(fp.read())
            fp.close()
            email.encoders.encode_base64(part)
        part.add_header('Content-Disposition', 'attachment',
                        filename=os.path.basename(attachment))
        message.attach(part)
    return (message, failed)


def send_report(body, attachments, mua, fromaddr, sendto, ccaddr, bccaddr,
                headers, package='x', charset="us-ascii", mailing=True,
                sysinfo=None,
                rtype='debbugs', exinfo=None, replyto=None, printonly=False,
                template=False, outfile=None, mta='', kudos=False,
                smtptls=False, smtphost='localhost',
                smtpuser=None, smtppasswd=None, paranoid=False, draftpath=None,
                envelopefrom=None):
    '''Send a report.'''

    failed = using_sendmail = False
    msgname = ''
    # Disable smtphost if mua is set
    if mua and smtphost:
        smtphost = ''

    # No, I'm not going to do a full MX lookup on every address... get a
    # real MTA!
    if kudos and smtphost == 'reportbug.debian.org':
        smtphost = 'packages.debian.org'

    body_charset = 'utf-8'

    tfprefix = tempfile_prefix(package)
    if attachments and not mua:
        (message, failed) = mime_attach(body, attachments, charset, body_charset)
        if failed:
            ewrite("Error: Message creation failed, not sending\n")
            mua = mta = smtphost = None
    else:
        message = _MIMEText_wrapper(body)

    # Standard headers
    message['From'] = fromaddr
    message['To'] = sendto

    for (header, value) in headers:
            message[header] = value

    if ccaddr:
        message['Cc'] = ccaddr

    if bccaddr:
        message['Bcc'] = bccaddr

    replyto = os.environ.get("REPLYTO", replyto)
    if replyto:
        message['Reply-To'] = replyto

    if mailing:
        message['Message-ID'] = email.utils.make_msgid('reportbug')
        message['X-Mailer'] = VERSION
        message['Date'] = email.utils.formatdate(localtime=True)
    elif mua and not (printonly or template):
        message['X-Reportbug-Version'] = VERSION_NUMBER

    addrs = [str(x) for x in (message.get_all('To', []) +
                              message.get_all('Cc', []) +
                              message.get_all('Bcc', []))]
    alist = email.utils.getaddresses(addrs)

    cclist = [str(x) for x in message.get_all('X-Debbugs-Cc', [])]
    debbugs_cc = email.utils.getaddresses(cclist)
    if cclist:
        del message['X-Debbugs-Cc']
        addrlist = ', '.join(cclist)
        message['X-Debbugs-Cc'] = addrlist

    # Drop any Bcc headers from the message to be sent
    if not outfile and not mua:
        try:
            del message['Bcc']
        except:
            pass

    message = message.as_string()
    if paranoid and not (template or printonly):
        pager = os.environ.get('PAGER', 'sensible-pager')
        try:
            with os.popen(pager, 'w') as p:
                p.write(message)
        except  Exception as e:
            # if the PAGER exits before all the text has been sent,
            # it'd send a SIGPIPE, so crash only if that's not the case
            if e.errno != errno.EPIPE:
                raise e
        if not ui.yes_no('Does your report seem satisfactory', 'Yes, send it.',
                         'No, don\'t send it.'):
            smtphost = mta = None

    filename = None
    if template or printonly:
        pipe = sys.stdout
    elif mua:
        pipe, filename = TempFile(prefix=tfprefix, dir=draftpath)
    elif outfile or not ((mta and os.path.exists(mta)) and not smtphost):
        # outfile can be None at this point
        if outfile:
            msgname = os.path.expanduser(outfile)
        else:
            msgname = '/var/tmp/%s.bug' % package
        if os.path.exists(msgname):
            try:
                os.rename(msgname, msgname + '~')
            except OSError:
                ewrite('Unable to rename existing %s as %s~\n',
                       msgname, msgname)
        try:
            pipe = open_write_safe(msgname, 'w')
        except OSError:
            # we can't write to the selected file, use a temp file instead
            fh, newmsgname = TempFile(prefix=tfprefix, dir=draftpath)
            ewrite('Writing to %s failed; '
                   'using instead %s\n', msgname, newmsgname)
            msgname = newmsgname
            # we just need a place where to write() and a file handler
            # is here just for that
            pipe = fh
    elif (mta and os.path.exists(mta)) and not smtphost:
        try:
            x = os.getcwd()
        except OSError:
            os.chdir('/')

        malist = [shlex.quote(a[1]) for a in alist]
        jalist = ' '.join(malist)

        faddr = email.utils.parseaddr(fromaddr)[1]
        if envelopefrom:
            envfrom = email.utils.parseaddr(envelopefrom)[1]
        else:
            envfrom = faddr
        ewrite("Sending message via %s...\n", mta)
        pipe = os.popen('%s -f %s -oi -oem %s' % (
            mta, shlex.quote(envfrom), jalist), 'w')
        using_sendmail = True

    # saving a backup of the report
    backupfh, backupname = TempFile(prefix=tempfile_prefix(package, 'backup'), dir=draftpath)
    ewrite('Saving a backup of the report at %s\n', backupname)
    backupfh.write(message)
    backupfh.close()

    if smtphost:
        toaddrs = [x[1] for x in alist]

        tryagain = True
        refused = None
        retry = 0
        while tryagain:
            tryagain = False
            ewrite("Connecting to %s via SMTP...\n", smtphost)
            try:
                conn = None
                # if we're using reportbug.debian.org, send mail to
                # submit
                if smtphost.lower() == 'reportbug.debian.org':
                    conn = smtplib.SMTP(smtphost, 587)
                else:
                    conn = smtplib.SMTP(smtphost)
                response = conn.ehlo()
                if not (200 <= response[0] <= 299):
                    conn.helo()
                if smtptls:
                    conn.starttls()
                    response = conn.ehlo()
                    if not (200 <= response[0] <= 299):
                        conn.helo()
                if smtpuser:
                    if not smtppasswd:
                        smtppasswd = ui.get_password(
                            'Enter SMTP password for %s@%s: ' %
                            (smtpuser, smtphost))
                    conn.login(smtpuser, smtppasswd)
                refused = conn.sendmail(fromaddr, toaddrs, message)
                conn.quit()
            except (socket.error, smtplib.SMTPException) as x:
                # If wrong password, try again...
                if isinstance(x, smtplib.SMTPAuthenticationError):
                    ewrite('SMTP error: authentication failed.  Try again.\n')
                    tryagain = True
                    smtppasswd = None
                    retry += 1
                    if retry <= 2:
                        continue
                    else:
                        tryagain = False

                # In case of failure, ask to retry or to save & exit
                if ui.yes_no('SMTP send failure: %s. Do you want to retry (or else save the report and exit)?' % x,
                             'Yes, please retry.',
                             'No, save and exit.'):
                    tryagain = True
                    continue
                else:
                    failed = True

                    fh, msgname = TempFile(prefix=tfprefix, dir=draftpath)
                    fh.write(message)
                    fh.close()

                    ewrite('Wrote bug report to %s\n', msgname)
        # Handle when some recipients are refused.
        if refused:
            for (addr, err) in refused.items():
                ewrite('Unable to send report to %s: %d %s\n', addr, err[0],
                       err[1])
            fh, msgname = TempFile(prefix=tfprefix, dir=draftpath)
            fh.write(message)
            fh.close()

            ewrite('Wrote bug report to %s\n', msgname)
    else:
        try:
            pipe.write(message)
            pipe.flush()
            if msgname:
                ewrite("Bug report written as %s\n", msgname)
        except IOError:
            failed = True
            pipe.close()

        if failed or (pipe.close() and using_sendmail):
            failed = True
            fh, msgname = TempFile(prefix=tfprefix, dir=draftpath)
            fh.write(message)
            fh.close()
            ui.long_message('Error: send/write operation failed, bug report '
                            'saved to %s\n', msgname)

    if mua:
        ewrite("Spawning %s...\n", mua.name)
        returnvalue = 0
        succeeded = False
        while not succeeded:
            returnvalue = mua.send(filename)
            if returnvalue != 0:
                ewrite("Mutt users should be aware it is mandatory to edit the draft before sending.\n")
                mtitle = 'Report has not been sent yet; what do you want to do now?'
                mopts = 'Eq'
                moptsdesc = {'e': 'Edit the message.',
                             'q': 'Quit reportbug; will save the draft for future use.'}
                x = ui.select_options(mtitle, mopts, moptsdesc)
                if x == 'q':
                    failed = True
                    fh, msgname = TempFile(prefix=tfprefix, dir=draftpath)
                    fh.write(message)
                    fh.close()
                    ewrite('Draft saved into %s\n', msgname)
                    succeeded = True
            else:
                succeeded = True

    elif not failed and (using_sendmail or smtphost):
        if kudos:
            ewrite('\nMessage sent to: %s\n', sendto)
        else:
            ewrite("\nBug report submitted to: %s\n", sendto)

        addresses = []
        for addr in alist:
            if addr[1] != email.utils.parseaddr(sendto)[1]:
                addresses.append(addr)

        if len(addresses):
            ewrite("Copies sent to:\n")
            for address in addrs:
                ewrite('  %s\n', address)

        if debbugs_cc and rtype == 'debbugs':
            ewrite("Copies will be sent after processing to:\n")
            for address in cclist:
                ewrite('  %s\n', address)

    if not (exinfo or kudos) and rtype == 'debbugs' and sysinfo and 'email' in sysinfo and not failed \
            and mailing:
        ewrite('\n')
        ui.final_message(
            """If you want to provide additional information, please wait to
receive the bug tracking number via email; you may then send any extra
information to %s (e.g. %s), where n is the bug number.  Normally you
will receive an acknowledgement via email including the bug report number
within an hour; if you haven't received a confirmation, then the bug reporting process failed at some point (reportbug or MTA failure, BTS maintenance, etc.).\n""",
            (sysinfo['email'] % 'n'), (sysinfo['email'] % 'nnnnnn'))

    # If we've stored more than one copy of the message, delete the
    # one without the SMTP headers.
    if filename and os.path.exists(msgname) and os.path.exists(filename):
        try:
            os.unlink(filename)
        except:
            pass

    if filename and os.path.exists(filename) and not mua:
        # Message is misleading if an MUA is used.
        ewrite("A copy of the report is stored as: %s\n" % filename)
    return
