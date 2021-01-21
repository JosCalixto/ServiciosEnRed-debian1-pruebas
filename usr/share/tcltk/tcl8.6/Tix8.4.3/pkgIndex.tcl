if {[catch {package require Tcl 8.4}]} return
package ifneeded Tix 8.4.3 \
    [list load [file join /usr/lib libTix8.4.3.so.1] Tix]
