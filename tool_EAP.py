#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - 
# Version 0.3, Last change on Oct 30, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

# EAP-AKA/AKA' client

import datetime
import time
import sys
import logging

#Next line is to include parent directory in PATH where libraries are
sys.path.append("..")
# Remove it normally

from libDiameter import *
import eap
import argparse

def Payload_Challenge_Response(ID,RAND,ETYPE, 
                               RAWIDENTITY='0121111234561000@wlan.mnc023.mcc262.3gppnetwork.org',
                               IK="2d346b8c456223bc7519823a0abc94fd",
                               CK="07fc3189172095ddce5b4ba2bfb70f7f",
                               XRES="e818fbf691ae3b97"):
    # Let's build EAP-Payload Challenge-Response AVP
    # Create EAP-Payload (empty)
    EAP=eap.EAPItem()
    # Set command code
    EAP.cmd=eap.EAP_CODE_RESPONSE
    # Set id 
    EAP.id=int(ID)
    # Set type
    #EAP.type=ETYPE
    EAP.type=eap.EAP_TYPE_AKA
    # Set sub-type
    EAP.stype=eap.dictEAPSUBname2type("AKA-Challenge")
    # RAND is copied from Challenge
    # These values can be calculated or entered manually
    #XRES,CK,IK,AK,AKS=eap.aka_calc_milenage(OP,Ki,RAND)
    # Or copy from MAA
    # IK=Identity-Key
    # CK=Confidentiality-Key
    # XRES=SIP-Authorization
    if EAP.type==eap.EAP_TYPE_AKAPRIME:
        # For AKA'
        KENCR,KAUT,MSK,EMSK,KRE=eap.akap_calc_keys(RAWIDENTITY,CK,IK)    
    else:
        # For AKA
        logging.debug('AKA EAP.type', EAP.type)
        logging.debug('IDENTITY', RAWIDENTITY)
        logging.debug('CK', CK)
        logging.debug('IK', IK)
        logging.debug('XRES', XRES )
        KENCR,KAUT,MSK,EMSK,MK=eap.aka_calc_keys(RAWIDENTITY,CK,IK)
        logging.debug('KAUT',str(KAUT))
    # Add AT_RES
    EAP.avps.append(("AT_RES",XRES))
    # Add AT_MAC as last
    eap.addMAC(EAP,KAUT,'') 
    # Do not add any AVPs after adding MAC
    Payload=eap.encode_EAP(EAP)
    # Payload now contains EAP-Payload AVP
    return Payload
    
def dump_EapPayload(msg):
    E=eap.decode_EAP(msg)
    print "="*30
    print eap.getEAPCodeName(E.code)
    (et,er)=eap.getEAPTypeName(E.type)
    if er==0:
        print "Type:",et
    if E.stype!=0:
       x=eap.dictEAPSUBtype2name(E.stype)
       print "Subtype:",x
    for avp in E.avps:
       (code,data)=avp
       print code,"=",data
    print "-"*30


def processEapPayload():
    #action="store_true")
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-e", "--encode", help='build EAP-Payload Challenge Response', action="store_true")
    group.add_argument("-d", "--decode", help='decode EAP-Payload Challenge Response')

    parser.add_argument("-i", "--identity", help="raw identity")
    parser.add_argument("-I", "--ik", help="IK")
    parser.add_argument("-C", "--ck", help="CK")
    parser.add_argument("-X", "--xres", help="XRES")

    args = parser.parse_args()
    
    if args.encode :
        identity = args.identity
        ik = args.ik.decode('base64').encode('hex')
        ck = args.ck.decode('base64').encode('hex')
        xres = args.xres.decode('base64').encode('hex')

        payload = Payload_Challenge_Response(eap.EAP_CODE_RESPONSE,"",eap.EAP_TYPE_AKA, identity, ik, ck, xres)

        print "="*30
        print 'EAP-Payload = {0}'.format(payload)
        print 'EAP-Payload.hex.base64 = {0}'.format(payload.decode("hex").encode("base64"))
        print "-"*30
    
    if args.decode:
        payload = args.decode.decode('base64').encode('hex') 
        dump_EapPayload(payload)

if __name__ == "__main__":

    #logging.basicConfig(level=logging.DEBUG)
    LoadDictionary("./dictDiameter.xml")
    eap.LoadEAPDictionary("./dictEAP.xml")

    processEapPayload()
    
    

######################################################        
# History
#       - Feb 12, 2019 - provide the EAP-Payload tool
