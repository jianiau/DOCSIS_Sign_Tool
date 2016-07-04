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

proc istime {S i} {
	if {! [string is digit $S] } {return 0}
	if {$i>=12} {return 0}
	return 1
}

proc setimage {} {
	global signing Sign_MFG
	if {$signing == "sign"} {
		.fr1.fr.en1 configure -state enable
		.fr1.fr.en2 configure -state disable 
		.fr1.fr.bt_sign configure -state enable -text "Sign"
		.fr1.fr.bt_cosign configure -state disable
		set Sign_MFG 1
		.fr2.lf_sign.mfg configure -state disable
	} else {
		.fr1.fr.en1 configure -state disable 
		.fr1.fr.en2 configure -state enable 
		.fr1.fr.bt_sign configure -state enable -text "Resign"
		.fr1.fr.bt_cosign configure -state enable
		set Sign_MFG 1
		.fr2.lf_sign.mfg configure -state disable
	}
}

proc set_docsis_ver {} {
	global DOCSIS_ver
	if {$DOCSIS_ver==3.0} {
		grid  forget .fr5
		grid .fr3 -row 2 -column 0 -sticky we -padx 5 -pady 5
	} else {
		grid  forget .fr3
		grid .fr5 -row 2 -column 0 -sticky we -padx 5 -pady 5
	}
}

proc ui_init {} {
	global mfg_cert mfg_key mfg_signtime
	global mso_cert mso_key mso_signtime
	global DOCSIS_ver signing Sign_MFG Sign_MSO CVCCA
	
	if {![file exist config.ini]} {
		close [open config.ini w]
	}
	
	set ini [ini::open config.ini]
	set mfg_cert(3.0)     [::ini::value $ini MFG cvc CVC/MFG/cert.pem]
	set mfg_key(3.0)      [::ini::value $ini MFG key CVC/MFG/key.pem]
	set mfg_signtime(3.0) [::ini::value $ini MFG signtime [clock format [clock seconds] -format %y%m%d000000] ]
	set mso_cert(3.0)     [::ini::value $ini MSO cvc CVC/MSO/cert.pem]
	set mso_key(3.0)      [::ini::value $ini MSO key CVC/MSO/key.pem]
	set mso_signtime(3.0) [::ini::value $ini MSO signtime [clock format [clock seconds] -format %y%m%d000000]]

	set mfg_cert(3.1)     [::ini::value $ini MFG31 cvc CVC_new/MFG/cert.pem]
	set mfg_key(3.1)      [::ini::value $ini MFG31 key CVC_new/MFG/key.pem]
	set mfg_signtime(3.1) [::ini::value $ini MFG31 signtime [clock format [clock seconds] -format %y%m%d000000] ]
	set mso_cert(3.1)     [::ini::value $ini MSO31 cvc CVC_new/MSO/cert.pem]
	set mso_key(3.1)      [::ini::value $ini MSO31 key CVC_new/MSO/key.pem]
	set mso_signtime(3.1) [::ini::value $ini MSO31 signtime [clock format [clock seconds] -format %y%m%d000000]]
	set CVCCA             [::ini::value $ini CVCCA cert CVC_new/cvcca.pem]

	set DOCSIS_ver [::ini::value $ini settings version 3.0]
	set Sign_MFG [::ini::value $ini settings MFG 1]
	set Sign_MSO [::ini::value $ini settings MSO 0]
	set signing [::ini::value $ini settings Sign sign]
	ini::close $ini
	
	if {$DOCSIS_ver=="3.0"} {
		.fr2.lf_ver.legacy invoke
	} else {
		.fr2.lf_ver.new	invoke
	}
	
	if {$signing=="sign"} {
		.fr1.fr.rb1 invoke
	} else {
		.fr1.fr.rb2 invoke	
	}
	
}

proc ini_save {save} {

	global mfg_cert mfg_key mfg_signtime
	global mso_cert mso_key mso_signtime
	global DOCSIS_ver signing Sign_MFG Sign_MSO CVCCA
	
	if {$save=="yes"} {
		set ini [ini::open config.ini]	
		::ini::set $ini MFG cvc $mfg_cert(3.0)
		::ini::set $ini MFG key $mfg_key(3.0)
		::ini::set $ini MFG signtime $mfg_signtime(3.0)
		::ini::set $ini MSO cvc $mso_cert(3.0)
		::ini::set $ini MSO key $mso_key(3.0)
		::ini::set $ini MSO signtime $mso_signtime(3.0)
		
		::ini::set $ini MFG31 cvc $mfg_cert(3.1)
		::ini::set $ini MFG31 key $mfg_key(3.1)
		::ini::set $ini MFG31 signtime $mfg_signtime(3.1)
		::ini::set $ini MSO31 cvc $mso_cert(3.1)
		::ini::set $ini MSO31 key $mso_key(3.1)
		::ini::set $ini MSO31 signtime $mso_signtime(3.1)
		
		::ini::set $ini CVCCA cert $CVCCA
		
		::ini::set $ini settings version $DOCSIS_ver
		::ini::set $ini settings MFG $Sign_MFG
		::ini::set $ini settings MSO $Sign_MSO
		::ini::set $ini settings Sign $signing
		::ini::commit $ini
		::ini::close $ini
	}
	set ::saveini 1
}

proc log_msg {msg {newline 1} {status default} {insert_index end}} {
	global log_text	
	if {$newline} {
		$log_text insert $insert_index "$msg\n"
		set index [$log_text index insert-1c]
	} else {
		$log_text insert $insert_index "$msg"
		set index [$log_text index insert]
	}	
	$log_text see end
	
	set len [string length $msg]
	if {$insert_index=="end"} {
		$log_text tag add $status $index-[set len]c $index
	} else {
		$log_text tag add $status $insert_index $insert_index+[set len]c
	}
}

bind .fr1.fr.en1 <Double-1> {
	set types {
		{{image Files} {.img .bin}}
		{{All Files} *}
	}
	set filename [tk_getOpenFile -filetypes $types -initialdir [pwd]]
	if {$filename != ""} {
		set image_unsigned $filename
	}
}

bind .fr1.fr.en2 <Double-1> {
	set types {
		{{image Files} {.p7b .img .bin}}
		{{All Files} *}
	}
	set filename [tk_getOpenFile -filetypes $types -initialdir [pwd]]
	if {$filename != ""} {
		set image_signed $filename
	}
}

bind .fr3.fr_mfg.en_cert <Double-1> {
	set types {
		{{image Files} {.pem .cer .crt}}
		{{All Files} *}
	}
	set filename [tk_getOpenFile -filetypes $types -initialdir [pwd]]
	if {$filename != ""} {
		set mfg_cert(3.0) $filename
	}
}

bind .fr3.fr_mfg.en_key <Double-1> {
	set types {
		{{image Files} {.pem .key .pri}}
		{{All Files} *}
	}
	set filename [tk_getOpenFile -filetypes $types -initialdir [pwd]]
	if {$filename != ""} {
		set mfg_key(3.0) $filename
	}
}

bind .fr3.fr_mso.en_cert <Double-1> {
	set types {
		{{image Files} {.pem .cer .crt}}
		{{All Files} *}
	}
	set filename [tk_getOpenFile -filetypes $types -initialdir [pwd]]
	if {$filename != ""} {
		set mso_cert(3.0) $filename
	}
}

bind .fr3.fr_mso.en_key <Double-1> {
	set types {
		{{image Files} {.pem .key .pri}}
		{{All Files} *}
	}
	set filename [tk_getOpenFile -filetypes $types -initialdir [pwd]]
	if {$filename != ""} {
		set mso_key(3.0) $filename
	}
}

bind .fr3.fr_mfg.en_cert <Double-1> {
	set types {
		{{image Files} {.pem .cer .crt}}
		{{All Files} *}
	}
	set filename [tk_getOpenFile -filetypes $types -initialdir [pwd]]
	if {$filename != ""} {
		set mfg_cert(3.0) $filename
	}
}

bind .fr3.fr_mfg.en_key <Double-1> {
	set types {
		{{image Files} {.pem .key .pri}}
		{{All Files} *}
	}
	set filename [tk_getOpenFile -filetypes $types -initialdir [pwd]]
	if {$filename != ""} {
		set mfg_key(3.0) $filename
	}
}

bind .fr3.fr_mso.en_cert <Double-1> {
	set types {
		{{image Files} {.pem .cer .crt}}
		{{All Files} *}
	}
	set filename [tk_getOpenFile -filetypes $types -initialdir [pwd]]
	if {$filename != ""} {
		set mso_cert(3.0) $filename
	}
}

bind .fr3.fr_mso.en_key <Double-1> {
	set types {
		{{image Files} {.pem .key .pri}}
		{{All Files} *}
	}
	set filename [tk_getOpenFile -filetypes $types -initialdir [pwd]]
	if {$filename != ""} {
		set mso_key(3.0) $filename
	}
}


bind .fr5.fr_mfg.en_cert <Double-1> {
	set types {
		{{image Files} {.pem .cer .crt}}
		{{All Files} *}
	}
	set filename [tk_getOpenFile -filetypes $types -initialdir [pwd]]
	if {$filename != ""} {
		set mfg_cert(3.1) $filename
	}
}

bind .fr5.fr_mfg.en_key <Double-1> {
	set types {
		{{image Files} {.pem .key .pri}}
		{{All Files} *}
	}
	set filename [tk_getOpenFile -filetypes $types -initialdir [pwd]]
	if {$filename != ""} {
		set mfg_key(3.1) $filename
	}
}

bind .fr5.fr_mso.en_cert <Double-1> {
	set types {
		{{image Files} {.pem .cer .crt}}
		{{All Files} *}
	}
	set filename [tk_getOpenFile -filetypes $types -initialdir [pwd]]
	if {$filename != ""} {
		set mso_cert(3.1) $filename
	}
}

bind .fr5.fr_mso.en_key <Double-1> {
	set types {
		{{image Files} {.pem .key .pri}}
		{{All Files} *}
	}
	set filename [tk_getOpenFile -filetypes $types -initialdir [pwd]]
	if {$filename != ""} {
		set mso_key(3.1) $filename
	}
}

bind .fr5.fr_ca.en_ca <Double-1> {
	set types {
		{{image Files} {.pem .key .pri}}
		{{All Files} *}
	}
	set filename [tk_getOpenFile -filetypes $types -initialdir [pwd]]
	if {$filename != ""} {
		set CVCCA $filename
	}
}

foreach item {.fr1.fr.en1 .fr1.fr.en2 .fr5.fr_ca.en_ca \
				.fr3.fr_mfg.en_cert .fr3.fr_mso.en_cert .fr3.fr_mfg.en_key .fr3.fr_mso.en_key\
				.fr5.fr_mfg.en_cert .fr5.fr_mso.en_cert .fr5.fr_mfg.en_key .fr5.fr_mso.en_key } {
	tkdnd::drop_target register $item DND_Files	
}

bind .fr1.fr.en1 <<Drop:DND_Files>> {
	set image_unsigned [lindex %D 0]
}

bind .fr1.fr.en2 <<Drop:DND_Files>> {
	set image_signed [lindex %D 0]
}


bind .fr3.fr_mfg.en_cert <<Drop:DND_Files>> {
	set mfg_cert(3.0) [lindex %D 0]
}

bind .fr3.fr_mfg.en_key <<Drop:DND_Files>> {
	set mfg_key(3.0) [lindex %D 0]
}

bind .fr3.fr_mso.en_cert <<Drop:DND_Files>> {
	set mso_cert(3.0) [lindex %D 0]
}

bind .fr3.fr_mso.en_key <<Drop:DND_Files>> {
	set mso_key(3.0) [lindex %D 0]
}

bind .fr5.fr_mfg.en_cert <<Drop:DND_Files>> {
	set mfg_cert(3.1) [lindex %D 0]
}

bind .fr5.fr_mfg.en_key <<Drop:DND_Files>> {
	set mfg_key(3.1) [lindex %D 0]
}

bind .fr5.fr_mso.en_cert <<Drop:DND_Files>> {
	set mso_cert(3.1) [lindex %D 0]
}

bind .fr5.fr_mso.en_key <<Drop:DND_Files>> {
	set mso_key(3.1) [lindex %D 0]
}

bind .fr5.fr_ca.en_ca <<Drop:DND_Files>> {
	set CVCCA [lindex %D 0]
}


$log_text tag configure error   -foreground #dd0000 -font {"Courier" {12} {}}
$log_text tag configure pass    -foreground #00a000 -font {"Courier" {12} {}}
$log_text tag configure warning -foreground #0000aa -font {"Courier" {12} {}}
$log_text tag configure default -foreground #000000 -font {"Courier" {12} {}}


ui_init
