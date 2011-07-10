#
# PKCS15 r/w profile for acos5 cards
# modeled after myeid.profile
#

cardinfo {
	label           = "ACOS5";
	manufacturer    = "ACS";
	min-pin-length	= 4;
	max-pin-length	= 8;
	pin-encoding	= ascii-numeric;
   	pin-pad-char	= 0xFF;
}

#
# The following controls some aspects of the PKCS15 we put onto
# the card.
#
pkcs15 {
    # Put certificates into the CDF itself?
    direct-certificates	= no;
    # Put the DF length into the ODF file?
    encode-df-length	= no;
    # Have a lastUpdate field in the EF(TokenInfo)?
    do-last-update	= no;
}

option default {
    macros {
        #protected	= READ=NONE, UPDATE=CHV1, DELETE=CHV2;
        #unprotected	= READ=NONE, UPDATE=CHV1, DELETE=CHV1;
		
	unusedspace-size = 510;
	odf-size	     = 255;
	aodf-size	     = 255;
	cdf-size	     = 1530;
	cdf-trusted-size = 510;
	prkdf-size	     = 1530;
	pukdf-size	     = 1530;
	dodf-size	     = 255;
    }
}

# Define reasonable limits for PINs and PUK
# Note that we do not set a file path or reference
# here; that is done dynamically.
PIN user-pin {
    reference  = 1;
    min-length = 4;
    max-length = 8;
    attempts   = 3;
    flags      = initialized, needs-padding;
}

PIN user-puk {
    min-length = 4;
    max-length = 8;
    attempts   = 10;
    flags      = needs-padding;
}

PIN so-pin {
    reference  = 3;
    auth-id    = FF;
    min-length = 4;
    max-length = 8;
    attempts   = 3;
    flags      = initialized, soPin, needs-padding;
}

PIN so-puk {
    min-length = 4;
    max-length = 8;
    attempts   = 10;
   flags       = needs-padding;
}

# Additional filesystem info.
# This is added to the file system info specified in the
# main profile.
filesystem {
    DF MF {
        path  = 3F00;
        type  = DF;
        acl	  = CREATE=$PIN, DELETE=$SOPIN;

    	# This is the DIR file
        EF DIR {	    
    	    file-id   = 2F00;
            structure = transparent;
	        size      = 128;
	        acl	      = READ=NONE, UPDATE=$SOPIN, DELETE=$SOPIN;
	    }

        DF PKCS15-AppDF {
 	        type      = DF;
	        file-id   = 501e;
            acl       = DELETE=$PIN, CREATE=$PIN;
	    
		# sort of like setcos.profile
		EF pinfile {
			file-id       = 6001;
			structure     = 0x0c;
			record-length = 18;
			size          = 18;
			ACL           = READ=NONE, UPDATE=NONE, DELETE=NONE
		}

		EF sefile {
			file-id       = 6004;
			structure     = 0x0c;
			record-length = 32;
			size          = 32;
			ACL           = READ=NONE, UPDATE=NONE, DELETE=NONE
		}


            EF PKCS15-ODF {
        	    file-id   = 5031;
                structure = transparent;
        	    size      = $odf-size;
	            acl       = READ=NONE, UPDATE=$PIN, DELETE=$SOPIN;
        	}

            EF PKCS15-TokenInfo {
        	   file-id	  = 5032;
	           structure  = transparent;
        	   acl	      = READ=NONE, UPDATE=$SOPIN, DELETE=$SOPIN;
            }

            EF PKCS15-UnusedSpace {
                file-id	  = 5033;
                structure = transparent;
                size	  = $unusedspace-size;
                acl	      = READ=NONE, UPDATE=$SOPIN, DELETE=$SOPIN;
            }

            EF PKCS15-AODF {
                file-id	  = 4411;
                structure = transparent;
                size	  = $aodf-size;
                acl	      = READ=NONE, UPDATE=$SOPIN, DELETE=$SOPIN;
            }

            EF PKCS15-PrKDF {
                file-id	  = 4412;
                structure = transparent;
                size	  = $prkdf-size;
                acl	      = *=NEVER, READ=NONE, UPDATE=$PIN, DELETE=$SOPIN;
            }

            EF PKCS15-PuKDF {
                file-id	  = 4414;
                structure = transparent;
                size	  = $pukdf-size;
                acl	      = *=NEVER, READ=NONE, UPDATE=$PIN, DELETE=$SOPIN;
            }

            EF PKCS15-CDF {
                file-id	  = 4413;
                structure = transparent;
                size	  = $cdf-size;
                acl	      = *=NEVER, READ=NONE, UPDATE=$PIN, DELETE=$SOPIN;
            }

            EF PKCS15-CDF-TRUSTED {
                file-id	  = 4415;
                structure = transparent;
                size	  = $cdf-trusted-size;
                acl	      = *=NEVER, READ=NONE, UPDATE=$PIN, DELETE=$SOPIN;
            }

            EF PKCS15-DODF {
                file-id	  = 4416;
                structure = transparent;
                size	  = $dodf-size;
                acl       = *=NEVER, READ=NONE, UPDATE=$PIN, DELETE=$SOPIN;
            }
            
            EF template-private-key {
                type      = internal-ef;
    	        file-id   = 4B11;	
    	        acl       = CRYPTO=$PIN, UPDATE=$PIN, DELETE=$PIN, GENERATE=$PIN;
            }
            
            EF template-public-key {
                structure = transparent;
                file-id	  = 5511;
                acl	      = READ=NONE, UPDATE=$PIN, DELETE=$PIN, GENERATE=$PIN;
            }

            EF template-certificate {
                file-id   = 4311;
                structure = transparent;
                acl       = READ=NONE, UPDATE=$PIN, DELETE=$PIN;
            }

            template key-domain {
                # This is a dummy entry - pkcs15-init insists that
                # this is present
                EF private-key {
                    file-id   = 4B11;
                    type      = internal-ef;
                    acl       = READ=NONE, UPDATE=$PIN, DELETE=$PIN, GENERATE=$PIN;
                }
                EF public-key {
                    file-id	  = 5511;
                    structure = transparent;
                    acl       = READ=NONE, UPDATE=$PIN, DELETE=$PIN, GENERATE=$PIN;
                }
		
                # Certificate template
                EF certificate {
                    file-id	  = 4311;
                    structure = transparent;
                    acl       = READ=NONE, UPDATE=$PIN, DELETE=$PIN;
                }
            }
	    }
    }
}
