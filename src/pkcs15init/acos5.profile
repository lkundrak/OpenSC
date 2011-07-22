#
# PKCS15 r/w profile for acos5 cards
# modeled after myeid.profile
#

cardinfo {
    label           = "ACOS5";
    manufacturer    = "ACS";
    min-pin-length  = 4;
    max-pin-length  = 8;
    pin-encoding    = ascii-numeric;
    pin-pad-char    = 0xFF;
}

#
# The following controls some aspects of the PKCS15 we put onto
# the card.
#
pkcs15 {
    # Put certificates into the CDF itself?
    direct-certificates = no;
    # Put the DF length into the ODF file?
    encode-df-length    = no;
    # Have a lastUpdate field in the EF(TokenInfo)?
    do-last-update      = no;
}

option default {
    macros {
        unprotected        = READ=NONE, UPDATE=NONE,   DELETE=NONE,   CRYPTO=NEVER;
	protected          = READ=NONE, UPDATE=$SOPIN, DELETE=$SOPIN, CRYPTO=$PIN;
	so-pin-flags       = initialized, needs-padding, soPin;

        unusedspace-size   = 510;
        odf-size           = 255;
        aodf-size          = 255;
        cdf-size           = 1530;
        cdf-trusted-size   = 510;
        prkdf-size         = 1530;
        pukdf-size         = 1530;
        dodf-size          = 255;
    }
}

option onepin {
    macros {
        unprotected	   = READ=NONE, UPDATE=NONE,   DELETE=NONE, CRYPTO=NEVER;
        protected	   = READ=NONE, UPDATE=$PIN,   DELETE=$PIN, CRYPTO=$PIN;
	so-pin-flags       = initialized, needs-padding;
    }
}

PIN user-pin {
    reference  = 1;
    attempts   = 3;
    flags      = initialized, needs-padding;
}

PIN user-puk {
    reference  = 2;
    attempts   = 10;
    flags      = needs-padding;
}

PIN so-pin {
    reference  = 3;
    auth-id    = FF;
    attempts   = 3;
    flags      = $so-pin-flags;
}

PIN so-puk {
    reference  = 4;
    attempts   = 10;
    flags      = needs-padding;
}

# Additional filesystem info.
# This is added to the file system info specified in the
# main profile.
filesystem {
    DF MF {
        path  = 3F00;
        type  = DF;

        # This is the DIR file
        EF DIR {            
            type      = EF;
            file-id   = 2F00;
            size      = 128;
            acl       = $unprotected;
        }

	# Here comes the application DF
        DF PKCS15-AppDF {
            type      = DF;
            file-id   = 5015;
            acl       = $unprotected;
            
            EF PKCS15-ODF {
                file-id       = 5031;
                size          = $odf-size;
                ACL           = $unprotected;
            }

            EF PKCS15-TokenInfo {
                file-id       = 5032;
                ACL           = $unprotected;
            }

            EF PKCS15-UnusedSpace {
                file-id       = 5033;
                size          = $unusedspace-size;
                ACL           = $unprotected;
            }

	    # pkcs15.profile uses 4401 as the file-id 
	    # for PKCS15-AODF, but on the acos5 that
	    # would usurp the Short File Identifier 0x01.
	    # so, we have to pick a different file-id
            EF PKCS15-AODF {
                file-id       = 4411;
                size          = $aodf-size;
                ACL           = $protected;
            }

            EF PKCS15-PrKDF {
                file-id       = 4402;
                size          = $prkdf-size;
                acl           = $protected;
            }

            EF PKCS15-PuKDF {
                file-id       = 4403;
                size          = $pukdf-size;
                acl           = $protected;
            }

            EF PKCS15-CDF {
                file-id       = 4404;
                size          = $cdf-size;
                acl           = $protected;
            }

            EF PKCS15-DODF {
                file-id       = 4405;
                size          = $dodf-size;
                ACL           = $protected;
            }

	    # unfortunately, the pinfile has to be readable
	    # to the user unblock pin in order to
	    # reset the retry counter
	    #
	    # this could be fixed if sc_pin_cmd could
	    # pass the desired retry count down
	    # to the driver.  if this is
	    # eventually done, then change
	    # the acl to READ=NEVER
            EF pinfile {
                file-id       = 6001;
                structure     = 0x0c;
                record-length = 18;
                size          = 18;
                ACL           = READ=CHV2, UPDATE=CHV2, DELETE=NEVER, CRYPTO=NEVER;
            }

            EF sefile {
                file-id       = 6004;
                structure     = 0x0c;
                record-length = 32;
                size          = 32;
                ACL           = READ=NONE, UPDATE=NEVER, DELETE=NEVER, CRYPTO=NEVER;
            }

            EF template-private-key {
                type          = internal-ef;
                file-id       = 4b11;       
                acl           = READ=NEVER, UPDATE=$SOPIN, DELETE=$SOPIN, CRYPTO=$PIN;
            }

            # this is a specially formatted version of the public key
            # for the acos5 hardware.  the ordinary pkcs public key is
            # in another file
            EF template-hw-public-key {
                type          = internal-ef;
                file-id       = 5b11;       
                 acl          = $protected;
            }

            EF template-public-key {
                file-id       = 5511;
                acl           = $protected;
            }

            EF template-certificate {
                file-id       = 4311;
                acl           = $protected;
            }
        }
    }
}
