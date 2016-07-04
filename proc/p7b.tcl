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

package require asn

oo::class create AttributeTypeAndValue {
	constructor {} {
		variable typevalue
		variable raw
    }
    method set {name value} {
    	variable typevalue
    	set typevalue($name) $value
    }
    method insert {name value} {
		variable typevalue
		if [info exist typevalue($name)] {
			set typevalue($name) [linsert $typevalue($name) end $value]
		} else {
			set typevalue($name) $value
		}
    }
	method get {name} {
		variable typevalue
		return $typevalue($name)
	}
	method setraw {rawdata} {
		variable raw
		set raw $rawdata
	}
	method getraw {} {
		variable raw
		return $raw
	}
	method getall {} {
		variable typevalue		
		foreach name [array names typevalue] {
			lappend ret [list $name $typevalue($name)]
		}
		return $ret
	}
}

proc asn::asnGetGeneralizedTime {data_var utc_var} {
    upvar 1 $data_var data $utc_var utc

    asnGetByte data tag
    if {$tag != 0x18} {
        return -code error \
            [format "Expected UTCTime (0x18), but got %02x" $tag]
    }

    asnGetLength data length
    asnGetBytes data $length bytes
    
    # this should be ascii, make it explicit
    set bytes [encoding convertfrom ascii $bytes]
    binary scan $bytes a* utc
    
    return
}

proc get_attribute {rawdata} {
	global oidname
	upvar $rawdata attribute
	::asn::asnGetSet attribute data
	::asn::asnGetSequence data data
	::asn::asnGetObjectIdentifier data oid
	::asn::asnRetag data 4
	::asn::asnGetOctetString data value	
	return [list [oid2name $oid] $value]
}

proc parse_AuthAttr {data obj} {
	::asn::asnGetSequence data oid_val
	::asn::asnGetObjectIdentifier oid_val oid
	::asn::asnGetSet oid_val val
	::asn::asnGetObjectIdentifier val oid2
	$obj set [oid2name $oid] [oid2name $oid2]
	
	
	::asn::asnGetSequence data oid_val
	::asn::asnGetObjectIdentifier oid_val oid
	::asn::asnGetSet oid_val val
	asn::asnGetUTCTime val stime
	$obj set [oid2name $oid] $stime

	::asn::asnGetSequence data oid_val
	::asn::asnGetObjectIdentifier oid_val oid
	::asn::asnGetSet oid_val val	
}

proc format_utc_time {utc} {
    if {[string length $utc]==13} {
		if {[scan $utc %2d%2d%2d%2d%2d%2d Y M D h m s]!=6} {return}
		if {$Y>50} {
			incr Y 1900
		} else {
			incr Y 2000
		}
	} else {
		scan $utc %4d%2d%2d%2d%2d%2d Y M D h m s
	}
	if {$M<1 || $M>12} {return}
	if {$D<1 || $D>31} {return}
	if {$h<0 || $h>23} {return}
	if {$m<0 || $m>59} {return}
	if {$s<0 || $s>59} {return}	
	return "$Y-[format %02d $M]-[format %02d $D]-[format %02d $h]:[format %02d $m]:[format %02d $s]"
}



proc oid2name {oid} {
	global oidname
	set oid [join $oid .]
	if [info exist oidname($oid)] {
		return $oidname($oid)
	} else {
		return $oid
	}
}

proc parse_cert {data cvc_obj} {
	::asn::asnGetSequence data certdata
	# TBSCertificate
	::asn::asnGetSequence certdata tbsdata

	#Version
	::asn::asnGetContext tbsdata contextNumber version
	::asn::asnGetInteger version ver
	$cvc_obj set version $ver

	# Serial Number
	::asn::asnRetag tbsdata 4
	::asn::asnGetOctetString tbsdata serial
	binary scan $serial H* serial
	set serial [string toupper $serial]
	$cvc_obj set serial [string toupper $serial]

	#Signature
	::asn::asnGetSequence tbsdata data
	::asn::asnGetObjectIdentifier data oid
	$cvc_obj set signAlg [oid2name $oid]

#sha1WithRSAEncryption
#sha256WithRSAEncryption
	#Issuer SEQUENCE
	::asn::asnGetSequence tbsdata Issuer

	set Issuer_obj [AttributeTypeAndValue new]
		
	while {[string length $Issuer]>0} {
		foreach {name value} [get_attribute Issuer] {
			$Issuer_obj insert $name $value
		}
	}	
	
	$cvc_obj set Issuer $Issuer_obj
	
	# valid Time
	::asn::asnGetSequence tbsdata data
	::asn::asnGetUTCTime data utc_var1
	
	set starttime [format_utc_time $utc_var1]
	$cvc_obj set starttime $starttime
	
	
	::asn::asnPeekTag data tag_var tagtype_var constr_var
	switch $tag_var {
		"23" {
			::asn::asnGetUTCTime data utc_var2
		}			
		"24" {
			::asn::asnGetGeneralizedTime data utc_var2
		}
	}
	
	set endtime [format_utc_time $utc_var2]
	$cvc_obj set endtime $endtime
	
	#Subject SEQUENCE
	::asn::asnGetSequence tbsdata subject

	set Subject [AttributeTypeAndValue new]
	$cvc_obj insert Subject $Subject
	
	while {[string length $subject]>0} {
		foreach {type value} [get_attribute subject] {
			$Subject set $type $value
		}		
	}
	
	#	::asn::asnGetSequence tbsdata PublicKeyInfo
	#	::asn::asnGetSequence PublicKeyInfo data
	#	::asn::asnGetObjectIdentifier data oid
	#	::asn::asnGetBitString PublicKeyInfo data
	#	set publickey [binary format B* $data]

	#	set Extensions_OPTIONAL $tbsdata
	#	::asn::asnGetSequence cvcdata sign_seq
	#	::asn::asnGetObjectIdentifier sign_seq oid
	#	::asn::asnGetBitString cvcdata data	
	#	set Signature_value [binary format B* $data]
	return 
}

proc parse_SignerInfo {data info_obj} {
	
	::asn::asnGetInteger data ver		
	::asn::asnGetSequence data Issuer_and_SN
	::asn::asnGetSequence Issuer_and_SN Issuer
	
	#while {[string length $Issuer]} {
	#	get_attribute Issuer
	#}
	
	set sn $Issuer_and_SN
	::asn::asnRetag sn 4	
	::asn::asnGetOctetString sn serial
	binary scan $serial H* serial
	set serial [string toupper $serial]
	$info_obj set serial $serial
	
	# DigestAlgorithm
	::asn::asnGetSequence data digestAlg
	::asn::asnGetObjectIdentifier digestAlg oid
	#::asn::asnGetNull null
	$info_obj set digestAlg [oid2name $oid]

	
	::asn::asnGetContext data contextNumber AuthenticateAttributes
	
	set newAuthAttr [AttributeTypeAndValue new]
	$info_obj set AuthAttr $newAuthAttr
	parse_AuthAttr $AuthenticateAttributes $newAuthAttr
#	$info_obj set signtime [parse_AuthenticateAttributes AuthenticateAttributes]
	$info_obj set signingTime [$newAuthAttr get signingTime]
	
	# digestEncryptionAlgorithm
	::asn::asnGetSequence data encAlg
	::asn::asnGetObjectIdentifier encAlg oid
	$info_obj set encAlg [oid2name $oid]
	return
}


proc parse_p7b {p7b p7b_obj} {	
	::asn::asnGetSequence p7b data
	$p7b_obj setraw [::asn::asnSequence $data]
	
	::asn::asnGetObjectIdentifier data oid
	$p7b_obj set type [oid2name $oid]

	::asn::asnGetContext data contextNumber_var

	::asn::asnGetSequence data data
	#version	
	::asn::asnGetInteger data ver
	$p7b_obj set version $ver
	
	#SET OF DigestAlgorithmIdentifier	
	::asn::asnGetSet data digestalg ;# SET OF DigestAlgorithmIdentifier
	::asn::asnGetSequence digestalg digestalg
	::asn::asnGetObjectIdentifier digestalg oid
	$p7b_obj set digestalg [oid2name $oid]

	
	::asn::asnGetSequence data content	
	::asn::asnGetObjectIdentifier content oid
	$p7b_obj set content_type [oid2name $oid]
	
	
	# 0xA0 Certificate(s)
	::asn::asnGetContext data contextNumber certificates
	set cert_number 0
	
	
	while {[string length $certificates]>0} {
		set newcert [AttributeTypeAndValue new]
		::asn::asnGetSequence certificates cert
		$newcert setraw [::asn::asnSequence $cert]
		parse_cert [::asn::asnSequence $cert] $newcert
		$p7b_obj set cert_$cert_number $newcert
		incr cert_number
		
	}
	$p7b_obj set cert_number $cert_number

	#SignerInfo
	::asn::asnGetSet data SignerInfo
	set signinfo_number 0
	while {[string length $SignerInfo]>0} {
		set newsigninfo [AttributeTypeAndValue new]
		::asn::asnGetSequence SignerInfo SignerInfo_data
		$newsigninfo setraw [::asn::asnSequence $SignerInfo_data]
		parse_SignerInfo $SignerInfo_data $newsigninfo
		$p7b_obj set signinfo_$signinfo_number $newsigninfo
		incr signinfo_number
	}
	$p7b_obj set signinfo_number $signinfo_number	
	set SignedContent [AttributeTypeAndValue new]
	$p7b_obj set SignedContent $SignedContent
	$SignedContent setraw $p7b
}

