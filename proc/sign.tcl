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

proc sign_cms {signer_cert signer_key alg signtime in_file out_file {cvcca ""}} {
	set ext ""
	if {$cvcca != ""} {
		set ext "-certfile $cvcca"
	}
	
	eval openssltcl cms -binary -sign -in $in_file -signer $signer_cert -inkey $signer_key -outform der \
		-signtime ${signtime}Z \
		-nosmimecap -md $alg \
		-out $out_file $ext
}

proc sign_smime {} {
}

proc open_binary_file {path access} {
	set fd [open $path $access]
	fconfigure $fd -translation binary
	return $fd
}

proc read_PKCS7_file {filename} {
	set fd [open_binary_file $filename r]
	set p7b [read $fd ]
	close $fd
	set pkcs7 [AttributeTypeAndValue new]
#	$pkcs7 setraw $p7b
	parse_p7b $p7b $pkcs7
	return $pkcs7
}

proc combine_PKCS7 {mfg mso} {
	set signdata ""
	append signdata [::asn::asnInteger 1]
	
	if {[$mfg get cert_number]==2} {
		# DOCSIS 3.1
		append signdata [::asn::asnSet [::asn::asnSequence [::asn::asnObjectIdentifier {2 16 840 1 101 3 4 2 1}] ] ] ;#sha256
		append signdata [::asn::asnSequence [::asn::asnObjectIdentifier {1 2 840 113549 1 7 1}]] ;#data
		append signdata [::asn::asnContextConstr 0 [[$mfg get cert_0] getraw] [[$mso get cert_0] getraw] [[$mfg get cert_1] getraw]]
	} else {
		# DOCSIS 3.0
		append signdata [::asn::asnSet [::asn::asnSequence [::asn::asnObjectIdentifier {1 3 14 3 2 26}] ] ] ;#sha1
		append signdata [::asn::asnSequence [::asn::asnObjectIdentifier {1 2 840 113549 1 7 1}]] ;#data
		append signdata [::asn::asnContextConstr 0 [[$mfg get cert_0] getraw] [[$mso get cert_0] getraw] ]
	}		
	append signdata [::asn::asnSet [[$mfg get signinfo_0] getraw] [[$mso get signinfo_0] getraw] ]
	set signdata [::asn::asnSequence $signdata]
	set signdata [::asn::asnContextConstr 0 $signdata]
	return [::asn::asnSequence [::asn::asnObjectIdentifier {1 2 840 113549 1 7 2}] $signdata] ;#signedData	
}

proc create_SignedContent {} {
	global signing
	global image_unsigned image_signed
	file mkdir [file join output temp]
	if {$signing == "sign"} {
		set fd [open_binary_file [file join output temp SignedContent] w]
		puts -nonewline $fd "\x1c\x00\x00"
		set fd_image [open_binary_file $image_unsigned r]
		puts -nonewline $fd [read $fd_image]
		close $fd
		close $fd_image
	} else {
		if [catch {read_PKCS7_file $image_signed} p7b] {
			log_msg "Read signed image fail. Please check the file." 1 error
			puts p7b=$p7b
			return 0
		}
		#set p7b [read_PKCS7_file $image_signed]		
		set fd_out [open_binary_file [file join output temp SignedContent] w]
		puts -nonewline $fd_out [[$p7b get SignedContent] getraw]
		close $fd_out
	}
	return 1
}

proc sign {} {
	global mfg_cert mfg_key mfg_signtime
	global mso_cert mso_key mso_signtime
	global DOCSIS_ver signing Sign_MFG Sign_MSO
	global image_unsigned image_signed CVCCA
		
	if {! [checkall]} {return}
	
	catch {file delete [file join output temp]}
	file mkdir [file join output temp]
	
	if {$signing == "sign"} {
		set out_name [file rootname [file tail $image_unsigned]].p7b
	} else {
		set out_name [file rootname [file tail $image_signed]]_new.p7b
	}
	
	if {$DOCSIS_ver==3.0} {
		set alg sha1
		set cvcca ""
	} else {
		set alg sha256
		set cvcca $CVCCA
	}
	
	if {![create_SignedContent]} {return 0}

	if [catch {sign_cms $mfg_cert($DOCSIS_ver) $mfg_key($DOCSIS_ver) $alg $mfg_signtime($DOCSIS_ver) [file join output temp SignedContent] [file join output temp mfg.p7b] $cvcca} ret] {
		log_msg "$ret" 1 error
		return 0
	}
	set mfg_p7b [read_PKCS7_file [file join output temp mfg.p7b]]
	set final_p7b [$mfg_p7b getraw]
	
	if {$Sign_MSO} {
		if [catch {sign_cms $mso_cert($DOCSIS_ver) $mso_key($DOCSIS_ver) $alg $mso_signtime($DOCSIS_ver) [file join output temp SignedContent] [file join output temp mso.p7b]} ret] {
			log_msg "$ret" 1 error
			return 0
		}
		
		set mso_p7b [read_PKCS7_file [file join output temp mso.p7b]]
		set final_p7b [combine_PKCS7 $mfg_p7b $mso_p7b]
	}
		
	set fd_in [open_binary_file [file join output temp SignedContent] r]
	set fd_out [open_binary_file [file join output $out_name] w]
	puts -nonewline $fd_out $final_p7b
	puts -nonewline $fd_out [read $fd_in]
	close $fd_in
	close $fd_out	
	
	log_msg "Sign image finished. " 1 pass
	log_msg "The signed image is at [file join output $out_name]" 1
	catch {file delete -force [file join output temp]}
}

proc co-sign {} {
	global mfg_cert mfg_key mfg_signtime
	global mso_cert mso_key mso_signtime
	global DOCSIS_ver signing Sign_MFG Sign_MSO
	global image_unsigned image_signed
	
	if {! [is_file_exist $mso_cert($DOCSIS_ver)] } {return 0}
	if {! [is_file_exist $mso_key($DOCSIS_ver)] } {return 0}
	if {! [checkUTCTime $mso_signtime($DOCSIS_ver)] } {return 0}
	
	if {$DOCSIS_ver == "3.1"} {
		# check CA
	}
	
	set out_name [file rootname [file tail $image_signed]]_co.p7b
	
	catch {file delete [file join output temp]}
	file mkdir [file join output temp]
	
	if {![create_SignedContent]} {return 0}

	set mfg_p7b [read_PKCS7_file $image_signed ]
	if {$DOCSIS_ver==3.0} {
		set alg sha1
	} else {
		set alg sha256
	}
	if [catch {sign_cms $mso_cert($DOCSIS_ver) $mso_key($DOCSIS_ver) $alg $mso_signtime($DOCSIS_ver) [file join output temp SignedContent] [file join output temp mso.p7b]} ret] {
		log_msg "$ret" 1 error
		return 0
	}
	set mso_p7b [read_PKCS7_file [file join output temp mso.p7b]]
	set final_p7b [combine_PKCS7 $mfg_p7b $mso_p7b]
	set fd_in [open_binary_file [file join output temp SignedContent] r]
	set fd_out [open_binary_file [file join output $out_name] w]
	puts -nonewline $fd_out $final_p7b
	puts -nonewline $fd_out [read $fd_in]
	close $fd_in
	close $fd_out	
	log_msg "Co-sign image finished. " 1 pass
	log_msg "The signed image is at [file join output $out_name]" 1
	
	catch {file delete [file join output temp]}
	
}

proc isleapyear {year} {
	if {($year % 400) && (($year % 4) || ($year % 100)==0)} {
		return 0
	} 
	return 1
}

proc checkUTCTime {UTCTime} {
	if {[string length $UTCTime]!=12} {
		log_msg "Signing time format is YYMMDDhhmmss" 1 error
		return 0
	}
	
	scan $UTCTime %2d%2d%2d%2d%2d%2d y m d H M S

	if {$y >= 50} {
		incr y 1900
	} else {
		incr y 2000
	}
	
	if {$m>12 || $m==0} {
		log_msg "The range of month is 01~12" 1 error
		return 0
	}
	
	if {[lsearch {1 3 5 7 8 10 12} $m ]>=0} {
		set max 31
	} else {
		set max 30
		if {$m==2} {
			set max [ expr 28 + [isleapyear $y] ]			
		}
	}
	
	if {$d>$max || $d==0} {
		if {$m==2} {
			log_msg "This month ($m) range is 01~$max" 1 error
			if {$max==29} {
				log_msg "This year ($y) is leap year" 1 error
			} else {
				log_msg "This year ($y) is common year" 1 error
			}
		} else {
			log_msg "This month ($m) range is 01~$max" 1 error
		}
		return 0
	}
	if {$H>23} {
		log_msg "The hours range is 00~23" 1 error
		return 0
	}
	if {$M>59} {
		log_msg "The minutes range is 00~23" 1 error
		return 0
	}
	if {$S>59} {
		log_msg "The seconds range is 00~23" 1 error
		return 0
	}	
	return 1
}

proc is_file_exist {filename {label ""}} {
	if {! [file exist $filename] } {
		if {$filename == ""} {
			if {$label != ""} {
				log_msg "$label: Please set filename." 1 error
			} else {
				log_msg "Please set filename" 1 error
			}
			return 0
		}
		if {$label != ""} {
			log_msg "$label: Can not find file $filename." 1 error
		} else {
			log_msg "Can not find file $filename" 1 error
		}
		return 0
	}
	return 1
}

proc checkall {} {
	global mfg_cert mfg_key mfg_signtime
	global mso_cert mso_key mso_signtime
	global DOCSIS_ver signing Sign_MFG Sign_MSO
	global image_unsigned image_signed CVCCA
	

	if {$signing=="sign"} {
		set filename $image_unsigned
		if {! [is_file_exist $filename "Unsigned image"] } {return 0}
	} else {
		set filename $image_signed
		if {! [is_file_exist $filename "Signed image"] } {return 0}
	}
		
	set signer 0
	if {$DOCSIS_ver == "3.1"} {
		# check CA
	}
	
	if { $Sign_MFG } {
		if {! [is_file_exist $mfg_cert($DOCSIS_ver) "DOCSIS $DOCSIS_ver MFG Cert"] } {return 0}
		if {! [is_file_exist $mfg_key($DOCSIS_ver) "DOCSIS $DOCSIS_ver MFG Key"] } {return 0}
		if {! [checkUTCTime $mfg_signtime($DOCSIS_ver) ] } {return 0}
		incr signer
	}
	if { $Sign_MSO } {
		if {! [is_file_exist $mso_cert($DOCSIS_ver) "DOCSIS $DOCSIS_ver MSO Cert"] } {return 0}
		if {! [is_file_exist $mso_key($DOCSIS_ver) "DOCSIS $DOCSIS_ver MSO Key"] } {return 0}
		if {! [checkUTCTime $mso_signtime($DOCSIS_ver) ] } {return 0}
		incr signer
	} 

	if {$signer == 0} {
		log_msg "Please select at least ine signer" 1 error
	}
		
	return 1
}


