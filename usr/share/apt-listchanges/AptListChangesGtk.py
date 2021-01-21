# vim:set fileencoding=utf-8 et ts=4 sts=4 sw=4:
from apt_listchanges import frontend

# check if gtk is available
import gi
gi.require_version('Gtk', '3.0')

from gi.repository import Gtk, GObject, GLib
import sys

from ALChacks import *


class gtk_frd(frontend):
    def flush_interface(self):
        while Gtk.events_pending():
            Gtk.main_iteration()

    def cb_close(self, widget):
        Gtk.main_quit()

    def __init__(self, *args):
        super().__init__(*args)
        self.builder = Gtk.Builder()
        self.builder.set_translation_domain("apt-listchanges")
        try:
            self.builder.add_from_file("apt-listchanges/apt-listchanges.ui")
        except GLib.Error:
            self.builder.add_from_file("/usr/share/apt-listchanges/apt-listchanges.ui")
        self.window_main = self.builder.get_object("window_main")
        handlers = {
            "on_button_close_clicked": self.cb_close,
            "on_window_main_destroy": self.cb_close,
        }
        self.progressbar_main = self.builder.get_object("progressbar_main")
        self.button_close = self.builder.get_object("button_close")
        self.label_header = self.builder.get_object("label_header")
        self.label_header_descr = self.builder.get_object("label_header_descr")
        self.label_header_descr.hide()
        self.textview_buf = self.builder.get_object("textview_main").get_buffer()

        self.set_title(_('apt-listchanges: Reading changelogs'))
        self.textview_buf.set_text('\n  ' + _('Reading changelogs. Please wait.'))
        self.builder.connect_signals(handlers)
        self.flush_interface()

    def display_output(self,text):
        self.label_header_descr.show()
        self.button_close.set_sensitive(True)
        self.textview_buf.set_text(self._render(text))
        Gtk.main()

    def update_progress(self, diff = 1):
        if not diff:
            return
        if not hasattr(self,'progress'):
            # First call
            self.progress = 0.0
            self.progressbar_main.show()
        self.progress += diff
        self.progressbar_main.set_fraction(self.progress / self.packages_count)
        self.progressbar_main.set_text(("%i%%" % (self.progress*100 / self.packages_count)))
        self.flush_interface()

    def progress_done(self):
        self.progressbar_main.hide()
        self.flush_interface()

    def confirm(self):
        m = Gtk.MessageDialog(self.window_main,
                              Gtk.DialogFlags.MODAL,
                              Gtk.MessageType.QUESTION,
                              Gtk.ButtonsType.YES_NO)
        m.set_default_response(Gtk.ResponseType.YES)
        m.set_markup("<big><b>%s</b></big>\n\n%s" % (_("Continue Installation?"), _("You can abort the installation if you select 'no'.")))
        if m.run() == Gtk.ResponseType.NO:
            return False
        return True

    def set_title(self, text):
        self.label_header.set_markup('<big><b>%s</b></big>' % text)
        self.window_main.set_title(text)
