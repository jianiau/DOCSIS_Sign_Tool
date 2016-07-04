#! /usr/bin/wish
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#  

set appPath [file normalize [info script]]
if {[file type $appPath] == "link"} {set appPath [file readlink $appPath]}
if {[namespace exists ::vfs]} {
	set appPath [file dirname $appPath]
} else {
	set appPath [file dirname $appPath]
}

lappend auto_path [file join $appPath lib]
package require tkdnd
package require inifile
package require openssltcl

set image_unsigned ""
set image_signed ""

source [file join proc dialog.tcl]
source [file join proc icons.tcl]
source [file join proc keynav.tcl]
source [file join proc sign.tcl]
source [file join proc p7b.tcl]
source [file join proc oids.tcl]

wm title . "DOCSIS Sign Image Tool"
wm withdraw .
wm transient .

ttk::frame .fr1
ttk::frame .fr2
ttk::frame .fr3
ttk::frame .fr4
ttk::frame .fr5

grid .fr1 -row 0 -column 0 -sticky we
grid .fr2 -row 1 -column 0 -sticky we -padx 5 -pady 5
grid .fr3 -row 2 -column 0 -sticky we -padx 5 -pady 5
grid .fr4 -row 3 -column 0 -sticky news

grid rowconfigure . 3 -weight 1
grid columnconfigure . 0 -weight 1


ttk::labelframe .fr1.fr -text "Sign Image"
ttk::radiobutton .fr1.fr.rb1 -text "Unsigned image" -variable signing -value sign -command {setimage}
ttk::radiobutton .fr1.fr.rb2 -text "signed image" -variable signing -value resign -command {setimage}
ttk::entry .fr1.fr.en1 -textvariable image_unsigned
ttk::entry .fr1.fr.en2 -textvariable image_signed
ttk::button .fr1.fr.bt_sign -text "Sign" -command {$log_text delete 1.0 end ; sign}
ttk::button .fr1.fr.bt_cosign -text "Co-sign" -command {$log_text delete 1.0 end ; co-sign}

grid columnconfigure .fr1 0 -weight 1

grid columnconfigure .fr1.fr 1 -weight 1

grid .fr1.fr -row 0 -column 0 -sticky we -padx 5 -pady 5
grid .fr1.fr.rb1 -row 0 -column 0 -sticky w -padx 5 -pady 5
grid .fr1.fr.rb2 -row 1 -column 0 -sticky w -padx 5 -pady 5
grid .fr1.fr.en1 -row 0 -column 1 -sticky we -padx 5 -pady 5
grid .fr1.fr.en2 -row 1 -column 1 -sticky we -padx 5 -pady 5
grid .fr1.fr.bt_sign -row 0 -column 2 -rowspan 2 -sticky ns -padx 5 -pady 5
grid .fr1.fr.bt_cosign -row 0 -column 3 -rowspan 2 -sticky ns -padx 5 -pady 5

grid columnconfigure .fr2 0 -weight 1
grid columnconfigure .fr2 1 -weight 1

ttk::labelframe .fr2.lf_ver -text "(Euro-)DOCSIS Version"
ttk::radiobutton .fr2.lf_ver.legacy -text "3.0" -variable DOCSIS_ver -value 3.0 -command {set_docsis_ver}
ttk::radiobutton .fr2.lf_ver.new -text "3.1" -variable DOCSIS_ver -value 3.1 -command {set_docsis_ver}

grid .fr2.lf_ver -row 0 -column 0 -sticky we -padx 5 -pady 5
grid columnconfigure .fr2.lf_ver 0 -weight 1
grid columnconfigure .fr2.lf_ver 1 -weight 1
grid .fr2.lf_ver.legacy -row 0 -column 0 -sticky we -padx 5 -pady 5
grid .fr2.lf_ver.new -row 0 -column 1 -sticky we -padx 5 -pady 5

ttk::labelframe .fr2.lf_sign -text "Signer"
ttk::checkbutton .fr2.lf_sign.mfg -text "MFG" -variable Sign_MFG
ttk::checkbutton .fr2.lf_sign.mso -text "MSO" -variable Sign_MSO

grid .fr2.lf_sign -row 0 -column 1 -sticky we -padx 5 -pady 5
grid columnconfigure .fr2.lf_sign 0 -weight 1
grid columnconfigure .fr2.lf_sign 1 -weight 1
grid .fr2.lf_sign.mfg -row 0 -column 0 -sticky we -padx 5 -pady 5
grid .fr2.lf_sign.mso -row 0 -column 1 -sticky we -padx 5 -pady 5

ttk::labelframe .fr3.fr_mfg -text "3.0 MFG Settings"
ttk::label .fr3.fr_mfg.cert -text "CVC"
ttk::label .fr3.fr_mfg.key -text "Private Key"
ttk::label .fr3.fr_mfg.time -text "Signing time"
ttk::entry .fr3.fr_mfg.en_cert -textvariable mfg_cert(3.0)
ttk::entry .fr3.fr_mfg.en_key -textvariable mfg_key(3.0)
ttk::entry .fr3.fr_mfg.en_time -textvariable mfg_signtime(3.0) -validate key -validatecommand {istime %S %i}

ttk::labelframe .fr3.fr_mso -text "3.0 MSO Settings"
ttk::label .fr3.fr_mso.cert -text "CVC"
ttk::label .fr3.fr_mso.key -text "Private Key"
ttk::label .fr3.fr_mso.time -text "Signing time"
ttk::entry .fr3.fr_mso.en_cert -textvariable mso_cert(3.0)
ttk::entry .fr3.fr_mso.en_key -textvariable mso_key(3.0)
ttk::entry .fr3.fr_mso.en_time -textvariable mso_signtime(3.0) -validate key -validatecommand {istime %S %i}

grid columnconfigure .fr3 0 -weight 1
grid columnconfigure .fr3 1 -weight 1

grid columnconfigure .fr3.fr_mfg 1 -weight 1
grid .fr3.fr_mfg -row 0 -column 0 -sticky we -padx 5 -pady 5
grid .fr3.fr_mfg.cert -row 0 -column 0 -sticky w -padx 5 -pady 5
grid .fr3.fr_mfg.key -row 1 -column 0 -sticky w -padx 5 -pady 5
grid .fr3.fr_mfg.time -row 2 -column 0 -sticky w -padx 5 -pady 5
grid .fr3.fr_mfg.en_cert -row 0 -column 1 -sticky we -padx 5 -pady 5
grid .fr3.fr_mfg.en_key -row 1 -column 1 -sticky we -padx 5 -pady 5
grid .fr3.fr_mfg.en_time -row 2 -column 1 -sticky we -padx 5 -pady 5

grid columnconfigure .fr3.fr_mso 1 -weight 1
grid .fr3.fr_mso -row 0 -column 1 -sticky we -padx 5 -pady 5
grid .fr3.fr_mso.cert -row 0 -column 0 -sticky w -padx 5 -pady 5
grid .fr3.fr_mso.key -row 1 -column 0 -sticky w -padx 5 -pady 5
grid .fr3.fr_mso.time -row 2 -column 0 -sticky w -padx 5 -pady 5
grid .fr3.fr_mso.en_cert -row 0 -column 1 -sticky we -padx 5 -pady 5
grid .fr3.fr_mso.en_key -row 1 -column 1 -sticky we -padx 5 -pady 5
grid .fr3.fr_mso.en_time -row 2 -column 1 -sticky we -padx 5 -pady 5

listbox .listbox
set SystemHighlight [ttk::style configure . -selectbackground]
set SystemHighlightText [ttk::style configure . -selectforeground]
set Systembg [ttk::style configure . -background]

ttk::frame .fr4.fr
grid .fr4.fr -row 0 -column 0 -sticky news -padx 5 -pady 5
grid columnconfigure .fr4 0 -weight 1
grid rowconfigure .fr4 0 -weight 1
grid columnconfigure .fr4.fr 0 -weight 1
grid rowconfigure .fr4.fr 0 -weight 1

set log_text [text .fr4.fr.text_log -bg $Systembg -font {Courier 11 {}} -fg black -height 20 -padx 5 -pady 5]
set sv [::ttk::scrollbar .fr4.fr.log_sv -orient vertical -command [list $log_text yview]]
$log_text configure -yscrollcommand [list $sv set]

grid $log_text -row 0 -column 0 -sticky news
grid $sv -row 0 -column 1 -sticky ns


ttk::labelframe .fr5.fr_mfg -text "3.1 MFG Settings"
ttk::label .fr5.fr_mfg.cert -text "CVC"
ttk::label .fr5.fr_mfg.key -text "Private Key"
ttk::label .fr5.fr_mfg.time -text "Signing time"
ttk::entry .fr5.fr_mfg.en_cert -textvariable mfg_cert(3.1)
ttk::entry .fr5.fr_mfg.en_key -textvariable mfg_key(3.1)
ttk::entry .fr5.fr_mfg.en_time -textvariable mfg_signtime(3.1) -validate key -validatecommand {istime %S %i}

ttk::labelframe .fr5.fr_mso -text "3.1 MSO Settings"
ttk::label .fr5.fr_mso.cert -text "CVC"
ttk::label .fr5.fr_mso.key -text "Private Key"
ttk::label .fr5.fr_mso.time -text "Signing time"
ttk::entry .fr5.fr_mso.en_cert -textvariable mso_cert(3.1)
ttk::entry .fr5.fr_mso.en_key -textvariable mso_key(3.1)
ttk::entry .fr5.fr_mso.en_time -textvariable mso_signtime(3.1) -validate key -validatecommand {istime %S %i}

ttk::labelframe .fr5.fr_ca -text "CVC CA"
ttk::label .fr5.fr_ca.lb_ca -text "CVC CA"
ttk::entry .fr5.fr_ca.en_ca -textvariable CVCCA

grid columnconfigure .fr5 0 -weight 1
grid columnconfigure .fr5 1 -weight 1

grid columnconfigure .fr5.fr_mfg 1 -weight 1
grid .fr5.fr_mfg -row 0 -column 0 -sticky we -padx 5 -pady 5
grid .fr5.fr_mfg.cert -row 0 -column 0 -sticky w -padx 5 -pady 5
grid .fr5.fr_mfg.key -row 1 -column 0 -sticky w -padx 5 -pady 5
grid .fr5.fr_mfg.time -row 2 -column 0 -sticky w -padx 5 -pady 5
grid .fr5.fr_mfg.en_cert -row 0 -column 1 -sticky we -padx 5 -pady 5
grid .fr5.fr_mfg.en_key -row 1 -column 1 -sticky we -padx 5 -pady 5
grid .fr5.fr_mfg.en_time -row 2 -column 1 -sticky we -padx 5 -pady 5

grid columnconfigure .fr5.fr_mso 1 -weight 1
grid .fr5.fr_mso -row 0 -column 1 -sticky we -padx 5 -pady 5
grid .fr5.fr_mso.cert -row 0 -column 0 -sticky w -padx 5 -pady 5
grid .fr5.fr_mso.key -row 1 -column 0 -sticky w -padx 5 -pady 5
grid .fr5.fr_mso.time -row 2 -column 0 -sticky w -padx 5 -pady 5
grid .fr5.fr_mso.en_cert -row 0 -column 1 -sticky we -padx 5 -pady 5
grid .fr5.fr_mso.en_key -row 1 -column 1 -sticky we -padx 5 -pady 5
grid .fr5.fr_mso.en_time -row 2 -column 1 -sticky we -padx 5 -pady 5

grid columnconfigure .fr5.fr_ca 1 -weight 1
grid .fr5.fr_ca -row 1 -column 0 -columnspan 2 -sticky we -padx 5 -pady 5
grid .fr5.fr_ca.lb_ca -row 0 -column 0 -sticky w -padx 5 -pady 5
grid .fr5.fr_ca.en_ca -row 0 -column 1 -sticky we -padx 5 -pady 5
tk::PlaceWindow .

wm protocol . WM_DELETE_WINDOW {
	ttk::dialog .saveFileDialog -title "Save file?" \
		-icon question -message "Save settings before closing?" \
		-buttons [list yes no ] \
		-labels [list yes "Save file" no "Don't save"] \
		-command ini_save
	vwait ::saveini
	destroy .
	exit
}


source [file join $appPath proc ui_proc.tcl]
