#
# urlutils.py - Simplified urllib handling
#
#   Written by Chris Lawrence <lawrencc@debian.org>
#   (C) 1999-2008 Chris Lawrence
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

import http.client
import urllib.request, urllib.parse, urllib.error
import urllib.request, urllib.error, urllib.parse
import getpass
import re
import socket
import shlex
import os
import sys
import webbrowser
import requests

from .exceptions import (
    NoNetwork,
)

from .__init__ import VERSION_NUMBER

UA_STR = 'reportbug/' + VERSION_NUMBER + ' (Debian)'


def decode(page):
    "gunzip or deflate a compressed page"
    # print page.info().headers
    encoding = page.info().get("Content-Encoding")
    if encoding in ('gzip', 'x-gzip', 'deflate'):
        from io import StringIO
        # cannot seek in socket descriptors, so must get content now
        content = page.read()
        if encoding == 'deflate':
            import zlib
            fp = StringIO(zlib.decompress(content))
        else:
            import gzip
            fp = gzip.GzipFile('', 'rb', 9, StringIO(content))
        # remove content-encoding header
        headers = http.client.HTTPMessage(StringIO(""))
        ceheader = re.compile(r"(?i)content-encoding:")
        for h in list(page.info().keys()):
            if not ceheader.match(h):
                headers[h] = page.info()[h]
        newpage = urllib.addinfourl(fp, headers, page.geturl())
        # Propagate code, msg through
        if hasattr(page, 'code'):
            newpage.code = page.code
        if hasattr(page, 'msg'):
            newpage.msg = page.msg
        return newpage
    return page


class HttpWithGzipHandler(urllib.request.HTTPHandler):
    "support gzip encoding"

    def http_open(self, req):
        return decode(urllib.request.HTTPHandler.http_open(self, req))


if hasattr(http.client, 'HTTPS'):
    class HttpsWithGzipHandler(urllib.request.HTTPSHandler):
        "support gzip encoding"

        def https_open(self, req):
            return decode(urllib.request.HTTPSHandler.https_open(self, req))


class handlepasswd(urllib.request.HTTPPasswordMgrWithDefaultRealm):
    def find_user_password(self, realm, authurl):
        user, password = urllib.request.HTTPPasswordMgrWithDefaultRealm.find_user_password(self, realm, authurl)
        if user is not None:
            return user, password

        user = input('Enter username for %s at %s: ' % (realm, authurl))
        password = getpass.getpass(
            "Enter password for %s in %s at %s: " % (user, realm, authurl))
        self.add_password(realm, authurl, user, password)
        return user, password


_opener = None


def urlopen(url, proxies=None, timeout=60, data=None):
    global _opener

    if not proxies:
        proxies = urllib.request.getproxies()

    headers = {'User-Agent': UA_STR,
               'Accept-Encoding': 'gzip;q=1.0, deflate;q=0.9, identity;q=0.5'}

    return requests.get(url, headers).text

    # req = urllib.request.Request(url, data, headers)
    #
    # proxy_support = urllib.request.ProxyHandler(proxies)
    # if _opener is None:
    #     pwd_manager = handlepasswd()
    #     handlers = [proxy_support,
    #                 urllib.request.UnknownHandler, HttpWithGzipHandler,
    #                 urllib.request.HTTPBasicAuthHandler(pwd_manager),
    #                 urllib.request.ProxyBasicAuthHandler(pwd_manager),
    #                 urllib.request.HTTPDigestAuthHandler(pwd_manager),
    #                 urllib.request.ProxyDigestAuthHandler(pwd_manager),
    #                 urllib.request.HTTPDefaultErrorHandler, urllib.request.HTTPRedirectHandler,
    #                 ]
    #     if hasattr(http.client, 'HTTPS'):
    #         handlers.append(HttpsWithGzipHandler)
    #     _opener = urllib.request.build_opener(*handlers)
    #     # print _opener.handlers
    #     urllib.request.install_opener(_opener)
    #
    # return _opener.open(req, timeout=timeout)


# Global useful URL opener; returns None if the page is absent, otherwise
# like urlopen
def open_url(url, http_proxy=None, timeout=60):
    # Set timeout to 60 secs (1 min), cfr bug #516449
    # in #572316 we set a user-configurable timeout
    socket.setdefaulttimeout(timeout)

    proxies = urllib.request.getproxies()
    if http_proxy:
        proxies['http'] = http_proxy

    try:
        page = urlopen(url, proxies, timeout)
    except urllib.error.HTTPError as x:
        if x.code in (404, 500, 503):
            return None
        else:
            raise
    except (socket.gaierror, socket.error, urllib.error.URLError) as x:
        raise NoNetwork
    except IOError as data:
        if data and data[0] == 'http error' and data[1] == 404:
            return None
        else:
            raise NoNetwork
    except TypeError:
        print("http_proxy environment variable must be formatted as a valid URI", file=sys.stderr)
        raise NoNetwork
    except http.client.HTTPException as exc:
        exc_name = exc.__class__.__name__
        message = "Failed to open %(url)r (%(exc_name)s: %(exc)s)" % vars()
        raise NoNetwork(message)
    return page


def launch_browser(url):
    if not os.system('command -v xdg-open >/dev/null 2>&1'):
        cmd = 'xdg-open ' + shlex.quote(url)
        os.system(cmd)
        return

    if webbrowser:
        webbrowser.open(url)
        return
