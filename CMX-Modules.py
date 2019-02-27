'''
irflow - Incident Response Workflow

This app enables security operations or an incident responder to leverage the Cisco security applications and tools to quickly assess hosts that have been compromised 
 and respond by isolating them from the network.  In addition, the responder can identify malicious sources of information and use Umbrella and Firepower to block them, 
 preventing other hosts from potential compromise from known malicious sources.
 
 This modules contains code to locate a given MAC address on a map using the Cisco CMX Location-based solution.  
 Furthermore, it will produce a floor image with that client MAC positioned on the image.

Copyright (c) 2018, Cisco Systems, Inc. All rights reserved.
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,

FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''

# -------------------------------------------------------------------
# This file contains a series of routines to locate clients with IOCs (by MAC address), and create a file based on that MAC
#   address, showing the location of that client.  Development was done primarily on CMX with v2 API calls.  Later I started
#   adding and modifying for v3 API calls, but I didn't have a v3 server that consistently provided me with data.  So you will
#   see tests in many routines like [if CMXversions.Loc_api_version == "v2":], but as a whole, this program does not support
#   v3 API's.  Primarily because much of the client/map data is included in the v2, "{}/api/location/v2/clients?macAddress={}"
#   call, but it requires additional API calls to get to the same point.   This is left to the reader.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# There is no "main()" program per-se for these routines.  You simply need to call the CMX_lookup() routine to get your client
# added to the InfectMacList and to generate an image of their location.  The three external-facing routines you maybe interested
# in are as follows.
#   CMX_lookup(mac) - queries CMX for the MAC address adds the client to the "InfectMacList" and produces a map of the client location.
#      Any subsiquent calls to this routine will query CMX for a current location and re-write the client location map.
#   Quarantine_CMXclient() - is another way to get a client into the system.  It does a call to CMX_look(), and then moves the client
#      directly onto the QuarantineMacList.
#   Purge_CMXclient() - Searches the InfectMacList and the QuarantineMacList for the Mac address and removes it from either list.
# Note:  There are some other routines in this file that offer other services beyond those required by IRflow.  I should clean them
#   out, or you can too.  They don't get called, so they don't hurt anything either.
# -------------------------------------------------------------------

import requests
try:
	requests.packages.urllib3.disable_warnings()        # ignore nuisance warning messages from "requests" right from the start!
except:
	pass
import json
import datetime, csv, base64, random, copy
from PIL import Image                                   # Image manipulation tools, From:  "pip install Pillow"
from pathlib import Path
#
# I create API "classes" for each call that I use.  I offload them to an external file for readability, and import only the ones I use.
# The API "class" may contain information specific to this routine and NOT part of the API response itself.  Those are identified with 
# a "Loc_" prefix within the class structures, and are marked as "# <<>> Not part of CMX data".
#from cmx_classes import CMX_version           			# Include CMX Version Class
#from cmx_classes import CMX_ClientCount                # Include CMX Client Count Class
#from cmx_classes import CMX_ClientLocation             # Include CMX Client Location Class
#from cmx_classes import CMX_MapsCount
from cmx_classes import *

#
# I keep a number of things into what I call "Environment Variable" file.  Generally this file contains sensitive information like credentials and tokens.
# You see different options commented out below.  Some are mutually exclusive and were commented out for testing with different sandboxes.  In a production
# environment, you would not need all these, but you would put your credentials into the file and import those as "CMX".
#from env_vars import Devnet_cmx_sandbox as CMX		# CMX (Devnet) locations Sandbox. v3 data but it returns empty API results
from env_vars import dCloud_apac_cmx_sandbox as CMX     # CMX APAC Sandbox.   v2 data but it returns API results
from env_vars import ThreatIcons as Tics                # This contains a list of threat icons that can be placed on a map
from env_vars import DotIcons as Dots                   # This contains a list of colored dots that can be used to identify user locations on a map
from env_vars import TinyLoc                            # Location of the tinyDB files
#from env_vars import ImageLoc                          # Location of the CMX image files.
#from requests.auth import HTTPBasicAuth				# This is Imported directly in the get_CMX_auth() module.


RunNumb = 0

# Initialized databases for storing data locally.  	Most of these will need to be incorporated into the global program structure.
# Most of this was for testing.  The thought was to put CMX data into a DB as well, but since it's already in a list, this was not needed.
#TinyDBs        = "IRFlow-db/"
#hosts_db       = TinyDBs+"hosts_db.json"						
#domains_db     = TinyDBs+"domains_db.json"
#threats_db     = TinyDBs+"threats_db.json"
#clients_db     = TinyDBs+"clients_db.json"		        # CMX Clients Database - Not going to build, but will use internal structures instead.

MapLocation		= "CMX/FloorPlans/"		                # Location for all static CMX Map files & Icons  [For now all maps are placed there manually - See get_CMX_maps()]
DefaultMap		= MapLocation+"blankfloor.jpg"	        # Default map to return in case of failure.
IconLocation    = "CMX/Icons/"                          # Location of map Icons
MacMaps         = "CMX/MACmaps/"                        # Default location for Client IOC location Maps
ThreatIcon      = IconLocation+"poiYellow.jpg"          # Choose a map icon to indicate a client with an IOC.

Debug          	= False									# Generic Debug toggle.  Turn this on to get all Debug diagnostics.
CMX_Init	  	= False 								# Initialization flag - Indicates if the CMX system has been initialized or not.
CMX_Sandbox		= True									# This is only required in a test environment with multiple disjoint systems.
DebugREQ       	= 0										# Get detailed response information from each "requests.responses" call.  "0" means "OFF".
														#   Otherwise a number from 1 to 98 (assigned to each API call) identifies which  call to
														#   provide information from.  The value of "99" will provide information for all CMX API calls.

CMXclientCount 	= ""                                    # Global Placeholder for CMX Client Count       [Class: CMX_ClientCount]
CMXversions    	= ""                                    # Global Placeholder for CMX Code Version       [Class: CMX_version]
MapsCounts      = ""                                    # Global Placeholder for CMX Campus information [Class: CMX_MapCounts]
CMXclientList  	= []                                    # Master List of ALL CMX Clients seen on CMX.  (Used for Sandbox Testing not for production.)
InfectMacList  	= []                                    # List of Infected MAC addresses (from "threats_db.json")
QuarantineMacList = []									# List of Quarantined MAC addresses.

CMXheaders = {											# Basic CMX API headers.  ["Authorization" filled in by CMX_get_auth()]
	'Authorization': "",
	'content-type': "application/json",
	'cache-control': "no-cache"
}



# -------------------------------------------------------------------
# get_CMX_version() - This routine identifies the version of code running on CMX.  I used this call as
#       a result of testing multiple sandboxes of different versions.  This is the only API call I know
#       of that can be executed prior to authenticating with CMX.  [See:  get_CMX_auth()]
#   The problem with multiple versions come with the API calls.  I want to use the latest API version
#   over one that has been deprecated.  Or worse yet trying to send a new API call to a system that
#   doesn't recognize it.  This code is relatively simplistic. If the code is 10.3 I use v2 API calls.
#   If it's 10.4 I use v3 API calls.  Other than that, I haven't planed for that use case.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#	
def get_CMX_version(host_ip):
    
    url = "https://{}/api/config/v1/version/image".format(host_ip)
    if Debug:
        print("<<>> get_CMX_version() - URL: ",url)

    try:
        response = requests.get(url, headers=CMXheaders, verify=False)
        if DebugREQ == 1 or DebugREQ == 99:
            print("<>> get_CMX_version() - URL: ",url)
            print("<>> get_CMX_version() - Headers:")
            print(json.dumps(CMXheaders, indent=4, sort_keys=True))
            print("<>> get_CMX_version() - requests_response:\t[",response,"]")
            print(json.dumps(response.json(), indent=4, sort_keys=True))
        if response.status_code in range(200,300):
            ver  = response.json()['cmx_image_version']
            conn = response.json()['cmx_rpm_versions'][0]
            wips = response.json()['cmx_rpm_versions'][1]
            cmx  = response.json()['cmx_rpm_versions'][2]
            CMXver = CMX_version(ver,conn,wips,cmx)             # Record the data collected
            ver1 = ver.split("_")
            ver2 = ver1[1]
            ver3 = ver2.split(".")
            if ver3[0] == 'CMX-10' and ver3[1] >= '4':          # I have no idea when this went to v3, but I know this version is.
                CMXver.Loc_api_version = "v3"
            else:
                CMXver.Loc_api_version = "v2"
        else:
            if Debug:
                print("<<>> get_CMX_version() - Network:\tResponse: [",response,"]")
            CMXver = CMX_version("none","none","none","none")   # Create a null structure with lowest common demoninator
            CMXver.Loc_api_version = "v2"
        return(CMXver)
    except:
        print("\n<<!>> get_CMX_version() -Fatal:  Error Executing Request:\tStatus: [",response.status_code,"]\tReason: [",response.reason,"]\n")
        CMXver = CMX_version("none","none","none","none")       # Create a null structure with lowest common demoninator
        CMXver.Loc_api_version = "v2"
        return(CMXver)


# -------------------------------------------------------------------
# get_CMX_auth() - This routine validates the basic authentication for CMX.
#    The CMX credentials are loaded from the "env_vars.py" file.  They can contain "username"/"password" pair,
#    and/or the Base64 encoded pair.  (From Postman.)  This routine will compute the Base64 when the user/password
#    credentials are supplied, or simply use the Base64 if not.  If all 3 are supplied the Base64 will be computed
#    and compared with what is provided.  If they don't match, the computed value will be used and a warning message
#    will be delivered before continuing.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#	
def get_CMX_auth(user,passwd,b64):
    global CMXheaders				                    # Make the modifications global for all API calls to use
    
    if user == "" or passwd == "":
        if b64 == "":
            print("\n<<!>> CMX_get_auth()-Failure:  No user credentials supplied. See 'env_vars.py'.\n")
            return(False)
    else:                                               # Compute Base64 of user credentials
        authstr  = user+':'+passwd
        authstrb = str.encode(authstr)
        auth = str(base64.b64encode(authstrb))
        bauth=auth.split("'")
        BasicAuth = "Basic "+bauth[1]
        if bauth[1] != b64:
            if Debug or DebugREQ == 2 or DebugREQ == 99:
                print("<<%>> CMX_get_auth()-Warning:  Computed Base64 does not match B64 string provided.  Using computed value.")
        CMXheaders['Authorization'] = BasicAuth
        if Debug or DebugREQ == 2 or DebugREQ == 99:
            print("<<>> CMX_get_auth()-Successful:  CMX Headers: [", CMXheaders,"]")
    return(True)
	

# -------------------------------------------------------------------
# get_CMX_MapsCount() - This routine pulls out all the building and floor information for your campus.  As I look at
#   this routine, I don't see a lot of pratical use for this particular application, but you may find it useful in other ways.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#	
def get_CMX_MapsCounts(host_ip):
    global MapsCounts
    
    url = "https://{}/api/config/v1/maps/count".format(CMX["host"])

    try:
        response = requests.get(url, headers=CMXheaders, verify=False)
        if DebugREQ == 3 or DebugREQ == 99:
            print("<>> get_CMX_MapsCounts() - URL: ",url)
            print("<>> get_CMX_CampusCounts() - Headers:")
            print(json.dumps(CMXheaders, indent=4, sort_keys=True))
            print("<>> get_CMX_MapsCounts() - requests_response:\t[",response,"]")
            print(json.dumps(response.json(), indent=4, sort_keys=True))
        if response.status_code == 200:
            Md = response.json()
            MC = CMX_MapsCount(Md["totalCampuses"],Md["totalBuildings"],Md["totalFloors"],Md["totalAps"])
            Cmp = Md['campusCounts']
            for Cc in range(MC.totalCampuses):              # Parse "Campus" Data
                Camp = CampusCounts(Cmp[Cc]['campusName'],Cmp[Cc]['totalBuildings'])
                Bld = Cmp[Cc]['buildingCounts']
                for Bc in range(Camp.totalBuildings):       # Parse "Buildings" belonging to each "Campus"
                    Bldg = BuildingCounts(Bld[Bc]['buildingName'],Bld[Bc]['totalFloors'])
                    Flr = Bld[Bc]['floorCounts']
                    for Fc in range(Bldg.totalFloors):
                        Floor = FloorCounts(Flr[Fc]['floorName'], Flr[Fc]['apCount'])
                        Bldg.floorCounts.append(copy.deepcopy(Floor))
                    Camp.buildingCounts.append(copy.deepcopy(Bldg))
                MC.campusCounts.append(copy.deepcopy(Camp))

            if DebugREQ == 3 or DebugREQ == 99:
                print("<<>> get_CMX_MapsCounts() - Campus Hierarchy")
                for i in range(MC.totalCampuses):
                    print (MC.campusCounts[i])
                    for j in range(MC.campusCounts[i].totalBuildings):
                        print(MC.campusCounts[i].buildingCounts[j])
                        for k in range(MC.campusCounts[i].buildingCounts[j].totalFloors):
                            print(MC.campusCounts[i].buildingCounts[j].floorCounts[k])
            MapsCounts = MC
        else:
            if Debug:
                print("<<>> get_CMX_MapsCounts() - Network:\tResponse: [",response,"]")
    except:
        print("\n<<!>> get_CMX_MapsCounts() -Fatal:  Error Executing Request:\tStatus: [",response.status_code,"]\tReason: [",response.reason,"]\n")

        
         
# -------------------------------------------------------------------
# get_CMX_clientCount() - Get count of Clients currently seen on CMX.  This call will always return a
#   response of the "CMX_ClientCount" class, even if it's all zeros, and/or the API call failed.
#
#   Caution:  There are two versions of this call.  The v2 call only provides a total count (with some
#       other worthless data.  While the v3 call breaks out the Total #, the Associated #, and # of
#       Probing clients Clients presently seen in CMX.  (This is more of a diagnostic API call verses
#       one that will be used in this environment right now.)  
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
def get_CMX_clientCount(host_ip):

    CMXccount = ""                                              # Empty class to start.
    
    if CMXversions.Loc_api_version == "v3":
        url = "https://{}/api/location/v3/clients/count".format(host_ip)
    else:
        url = "https://{}/api/location/v2/clients/count".format(host_ip)
    if Debug:
        print("<<>> get_CMX_clientCount() - URL: ",url)

    try:
        response = requests.get(url, headers=CMXheaders, verify=False)
        if  DebugREQ == 6 or DebugREQ == 99:
            print("<>> get_CMX_clientCount() - URL: ",url)
            print("<>> get_CMX_clientCount() - Headers:")
            print(json.dumps(CMXheaders, indent=4, sort_keys=True))
            print("<>> get_CMX_clientCount() - requests_response:\t[",response,"]")
            print(json.dumps(response.json(), indent=4, sort_keys=True))
            print()
        if response.status_code in range(200,300):
            if CMXversions.Loc_api_version == "v3":
                tc = response.json()['totalCount']
                ac = response.json()['associatedCount']
                pc = response.json()['probingCount']
                CMXccount = CMX_ClientCount(ac,pc,tc)           # Record the data collected
                CMXccount.Loc_apiVersion = "v3"                 # Change the version info
            else:
                dt = response.json()['deviceType']              # Not Interested in this field
                dq = response.json()['deviceQueryString']       # Not Interested in this field
                tc = response.json()['count']                   # This is really the only one I'm interested in
                CMXccount = CMX_ClientCount(tc,0,0)             # Record the data collected
                CMXccount.Loc_apiVersion = "v2"                 # Change the version info
            CMXccount.Loc_time = get_TimeStamp()                # Add the timestamp to the data
            return(CMXccount)
        else:
            if Debug:
                print("<<>> get_CMX_clientCount() - Network:\tResponse: [",response,"]")
            CMXccount = CMX_ClientCount(0,0,0)                  # Create an empty class
            CMXccount.Loc_time = get_TimeStamp()                # Add the timestamp to the data
            return(CMXccount)

    except:
        print("\n<<!>> get_CMX_clientCount() -Fatal:  Error Executing Request:\tStatus: [",response.status_code,"]\tReason: [",response.reason,"]\n")
        CMXccount = CMX_ClientCount(0,0,0)                      # Create an empty class
        CMXccount.Loc_time = get_TimeStamp()                    # Add the timestamp to the data
        return(CMXccount)


# -------------------------------------------------------------------
# get_all_CMX_clients() -  Returns a list of all Clients "presently" seen in CMX.
#   While there are two implementations of this API call, the data returned by both versions is
#   very similar.  I kept them separate, since I have two different test sandboxes to deal with.
#  Note:  In the production version, this call would not be necessary, as you would have multiple
#	systems on the same network.  This is only needed to tie the sandboxes together.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
def get_all_CMX_clients(host_ip):

    CMXcList = []                                           # Local CMX Client List
    
    if not CMX_Init:                                        # Chances are this will NOT be called prior to CMX_init(), but just in case.
        CMX_init()                                      

    if CMXversions.Loc_api_version == "v3":
        url = "https://{}/api/location/v3/clients".format(host_ip)
    else:
        url = "https://{}/api/location/v2/clients".format(host_ip)
    if Debug:
        print("<<>> get_all_CMX_clients() - URL: ",url)

    try:
        response = requests.get(url, headers=CMXheaders, verify=False)
        if DebugREQ == 5 or DebugREQ == 99:
            print("<>> get_all_CMX_clients() - URL: ",url)
            print("<>> get_all_CMX_clients() - Headers:")
            print(json.dumps(CMXheaders, indent=4, sort_keys=True))
            print("<>> get_all_CMX_clients() - requests_response:\t[",response,"]")
            print(json.dumps(response.json(), indent=4, sort_keys=True))
            print()
        if response.status_code in range(200,300):
            if CMXversions.Loc_api_version == "v3":
                CMXcList = parse_CMX_v3_clients(response.json())           # Convert (v3 API) JSON to list of class "CMX_ClientLocation" data
            else:
                CMXcList = parse_CMX_v2_clients(response.json())           # Convert (v2 API) JSON to list of class "CMX_ClientLocation" data
            if len(CMXcList) == 0:
                if Debug:
                    print("<<%>> get_all_CMX_clients() - Good API response, but no Client Data received.")
                CMXcList = []
        else:
            if Debug:
                print("<<%>> get_all_CMX_clients() - Bad API Response: [",response,"]")
            CMXcList = []
        return(CMXcList)

    except:
        print("\n<<!>> get_all_CMX_clients() -Fatal:  Error Executing Request:\tStatus: [",response.status_code,"]\tReason: [",response.reason,"]\n")
        CMXcList = []
        return(CMXcList)


# -------------------------------------------------------------------
# parse_CMX_v3_clients() - Parses the JSON response to the "/api/location/v3/clients" API call.
#   and places individual entries into a global master list of clients seen on CMX.
# NOTE:  This routine remains untested. 
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
def parse_CMX_v3_clients(jsonR):
    Clist = []
    
    if Debug:
        print("<<!>> parse_CMX_v3_clients() - Processing CMX API v3 API Clients is not yet supported.")
    return(False)


# -------------------------------------------------------------------
# parse_CMX_v2_clients() - Parses the JSON response to the "/api/location/v2/clients" API call.
#   and places individual entries into a global master list of clients seen on CMX.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
def parse_CMX_v2_clients(jsonR):
    Clist = []                                      # Parsed list of CMX Clients

    if Debug:
        print("<<>> parse_CMX_v2_clients() - Entries Delivered: ",len(jsonR))
    
    TimeStamp = get_TimeStamp()
    try:
        for cl in range(len(jsonR)):
            a1 = jsonR[cl]["macAddress"]
            a2 = jsonR[cl]["manufacturer"]
            a3 = jsonR[cl]["mapCoordinate"]["unit"]
            a4 = jsonR[cl]["mapCoordinate"]["x"]
            a5 = jsonR[cl]["mapCoordinate"]["y"]
            a6 = jsonR[cl]["mapInfo"]["floorDimension"]["height"]
            a7 = jsonR[cl]["mapInfo"]["floorDimension"]["length"]
            a8 = jsonR[cl]["mapInfo"]["floorDimension"]["offsetX"]
            a9 = jsonR[cl]["mapInfo"]["floorDimension"]["offsetY"]
            b1 = jsonR[cl]["mapInfo"]["floorDimension"]["unit"]
            b2 = jsonR[cl]["mapInfo"]["floorDimension"]["width"]
            b3 = jsonR[cl]["mapInfo"]["floorRefId"]
            b4 = jsonR[cl]["mapInfo"]["image"]["height"]
            b5 = jsonR[cl]["mapInfo"]["image"]["imageName"]
            b6 = jsonR[cl]["mapInfo"]["image"]["maxResolution"]
            b7 = jsonR[cl]["mapInfo"]["image"]["size"]
            b8 = jsonR[cl]["mapInfo"]["image"]["width"]
            b9 = jsonR[cl]["mapInfo"]["image"]["zoomLevel"]
            c  = jsonR[cl]["mapInfo"]["mapHierarchyString"]
            client = CMX_ClientLocation(a1,a2,a3,a4,a5,a6,a7,a8,a9,b1,b2,b3,b4,b5,b6,b7,b8,b9,c)
            client.Loc_time = TimeStamp
            Clist.append(client)
        if Debug:
            print("<<>> parse_CMX_v2_clients() - Entries Parsed: ",len(Clist))

    except:
        print("\n<<!>> parse_CMX_v2_clients() -Fatal:  Error while parsing Client JSON data.\n")
        return([])
    return(Clist)



# -------------------------------------------------------------------
# Map_CMXclient() - Positions threat icon on a map locating a client identified as having an IOC.
#    Maps are in the folder "MacMaps"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# 
def Map_CMXclient(cmxClient):

    if Debug:
        print("<<>> Map_CMXclient() - Location",cmxClient)
    
    if CMXversions.Loc_api_version == "v2":                     # Is this data from a v2 API call?
        xcord = round(cmxClient.map_xcord)
        ycord = round(cmxClient.map_ycord)
        floorMap = cmxClient.floorimage_imageName
        cmac  = cmxClient.macAddress
    else:                                                       # Otherwise we're looking at a v3 API call.
        xcord = round(cmxClient.locationCoordinateX)
        ycord = round(cmxClient.locationCoordinateY)            #
        floorMap = "tbd"                                        # This takes more work that needs to be done.
        cmac  = cmxClient.deviceId
    floorImage = MapLocation +  floorMap   
    if Debug:
        print("<<>> Map_CMXclient() - Location (",xcord,",",ycord,")\t[",floorMap,"]")
    for c in cmac:
        if c == ':':
            mc = cmac.replace(c, '_')
    ofname = MacMaps + mc + ".png"
    mapfile = Path(floorImage)
    if not mapfile.is_file():
        if Debug:
            print("<<%>> Map_CMXclient() - [",floorImage,"] does not exist.  Using default map ",DefaultMap)
        floorImage = DefaultMap
    floorImg  = Image.open(floorImage)
    clientIOC = Image.open(ThreatIcon)
    floorImg.paste(clientIOC,(xcord,ycord))
    floorImg.save(ofname)
    return()



# -------------------------------------------------------------------
# get_TimeStamp() - Returns a string containing the current time.  "yy-mm-dd hh:mm:ss"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
def get_TimeStamp():
    now = datetime.datetime.now()
    return(now.strftime("%Y-%m-%d %H:%M:%S"))
    

# -------------------------------------------------------------------
# CMX_init() - Official startup procedure for the CMX modules.  This routine only needs to be called once, and that will
#	occur upon the first call made to CMX.  This routine gets called when the first CMX lookup is made.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#   Step 1. Since I'm working with Sanboxes with different code versions I must Identify the version being used to make the
#       correct API call (CMX version as v2 or v3) [CMXversions].  This particular call does not require credentails to execute.
#   Setp 2. CMX authentication is "Basic" username/password.  Validate that information and insert it into the
#       CMXheaders dictionary.  (This will be used for all remaining CMX API calls).
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#   These remaining steps were unnecessary in the production code.  I kept some of the code in this file but commented out
#   the actual calls.  (To be cleaned up later.)
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#   Step 3. Thes next call is to get a map of the campus.  After doing this I did not need it for production, but the
#       code remains in the program.  The hierarchy of your campus is in the variable [CMX_MapsCounts].
#   Step 4. Next I get the count of clients from CMX [CMXclientCount]. Once again this action is more diagnostic than it
#       is required.
#   Step 5. Next I create a master list [CMXclientList] of CMX clients currently seen in CMX.  This is only required for
#       sandbox testing because I need some way to map MAC addresses present in the CMX Sandbox with those of the other
#       systems we're using.  If for any reason the API fails to return data, (sometimes the API call was successful, but
#       the sandbox but failed to deliver any data). In order to get around this I switched modes and populate the master
#       list with data collected and stored in a CSV file.  This condition is identified by the global "csvData = True" flag.
#       21-Feb-19 Removed get_CMX_csvData() after determining the format was now wrong after they changed sandbox API's.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
def CMX_init():
    global CMXversions, CMX_Init, CMX_ClientLocation
    
    if Debug or DebugREQ == 4:
        print("<<>> CMX_init() - Startup")
        
# Step 1. Determine the running CMX Version
    CMXversions = get_CMX_version(CMX["host"])          # Identify the CMX version we're working with.
    if CMXversions.Loc_api_version == "v2":
        from cmx_classes import CMX_ClientLocation_v2 as CMX_ClientLocation   # I think this changes with v3, which also messes up some of the logic of maps and things.
    else:
        from cmx_classes import CMX_ClientLocation_v3 as CMX_ClientLocation   # CAUTION:  This is not fully implemented and will fail.
        print("\n<<!>> CMX_init()-Warning:  Attempt to access CMX API-v3 server.  This code is not set up for that now.\n")
        return(False)
        
# Step 2. Using the username/password credentials in the env_vars file, create an authentication header for our calls.
#   this "Authentication" - basically fills in the CMXheaders "Authentication" field.
    if not get_CMX_auth(CMX["username"],CMX["password"],CMX["Base64"]):
        print("\n<<!>> CMX_init()-Warning:  Failure to authenticate user.  Check CMX credentials and try again.\n")
        return(False)
    else:
        CMX_Init = True					# Set the flag saying we've completed the process.
    return(True)


# -------------------------------------------------------------------
# get_CMX_maps() - This module was intended to download an individual CMX maps from the system.
#	- When working with the CMX sandboxes, the dCloud sandbox always returned a "System Error" with all map-related calls
#	- When working with the DevNet sandbox, I got better responses but was unable to get the map (except once) in a browser window
#	Clearly this process needs to be automated, but the resources I have available don't allow it to occur.  
#	The problem I see with full automation from this system is with the two API calls marked with an "*".  They say to invoke them
#		within a browser window to download the image.  I'm not sure if this indicates a system limitation or a non-automatable feature.
#	When Operational:  All Maps will be placed into the folder MapLocation = "CMX/FloorPlans"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -	
# Map resources API calls
#	Get count of all map elements - /api/config/v1/maps/count
#	Get a list of all Building names - /api/config/v1/maps/building/list
#	Get a list of all Building names - /api/config/v1/maps/building/list/:name
#	Get a list of all Floor names - /api/config/v1/maps/floor/list
#	Get a list of all Floor names - /api/config/v1/maps/floor/list/:name
#	Get all maps - /api/config/v1/maps
#	Get campus by name - /api/config/v1/maps/info/:campusName
#	Get building by name inside specific campus - /api/config/v1/maps/info/:campusName/:buildingName
#	Get floor inside specific building and specific campus - /api/config/v1/maps/info/:campusName/:buildingName/:floorName
#	* Get floor image - /api/config/v1/maps/image/:campusName/:buildingName/:floorName
#	* Get image by image name - /api/config/v1/maps/imagesource/:imageName
#	*Please invoke this API from a browser window to download the image.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -	
# 
def get_CMX_map(mapName):
	mapLoc = MapLocation + mapName
	try:
		mf = open(mapLoc, 'r')
		mf.close()
	except:
		print("<<%>> get_CMX_maps() - Map not Found: ",mapLoc)
		print("<<->> Download map file to: ", MapLocation)
		print("<<->> Using default map: ", mapDef)
		return(mapDef)
	return(mapLoc)



# -------------------------------------------------------------------
# CMX_lookup() - This is the official entry point to the CMX routines.  Once an infected MAC is identified,
#   this routine is called with its MAC address, which begins the task of populating the "InfectMacList".
#   Each time this is done, a Map is created with the location of that client.  In addition, any time a call
#   is made to change the status of the infected MAC, this routine is called to update the location of that
#   device.
#   NOTE:  While a distinction is made between v2 and v3, I have no way to test v3 on a live server.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
def CMX_lookup(mac):
    
    CMXclient = []                              # Parsing routine wants to return a list.  So for now I call it a list.

    if not CMX_Init:                            # Make sure the CMX initialization sequence has occured first.
        CMX_init()
    else:
        if CMXversions.Loc_api_version == "v3":
            url = "https://{}/api/location/v3/clients?macAddress={}".format(CMX["host"],mac)
        else:
            url = "https://{}/api/location/v2/clients?macAddress={}".format(CMX["host"],mac)
    if Debug:
        print("<<>> CMX_lookup() - URL: ",url)

    try:
        response = requests.get(url, headers=CMXheaders, verify=False)
        if DebugREQ == 7 or DebugREQ == 99:
            print("<>> CMX_lookup() - URL: ",url)
            print("<>> CMX_lookup() - Headers:")
            print(json.dumps(CMXheaders, indent=4, sort_keys=True))
            print("<>> CMX_lookup() - requests_response:\t[",response,"]")
            print()
        if response.status_code == 200:
            if DebugREQ == 7 or DebugREQ == 99:
                print(json.dumps(response.json(), indent=4, sort_keys=True))
            if CMXversions.Loc_api_version == "v2":
                CMXclient = parse_CMX_v2_clients(response.json())       # Convert JSON to list of class "CMX_ClientLocation" data
                if len(CMXclient) == 0:
                    if Debug:
                        print("<<%>> CMX_lookup() - Good API v2 response, but no Client Data parsed.")
                    CMXclient = []
            elif CMXversions.Loc_api_version == "v3":
                CMXclient = parse_CMX_v3_clients(response.json())       # Convert JSON to list of class "CMX_ClientLocation" data
                if len(CMXclient) == 0:
                    if Debug:
                        print("<<%>> CMX_lookup() - Good API v3 response, but no Client Data parsed.")
                    CMXclient = []
        if len(CMXclient) == 0:
            if Debug: 
                print("<>> CMX_lookup() - response code not 200 or Error parsing JSON:  ",response.status_code)
            if CMXversions.Loc_api_version == "v2":
                CMXclient.append(Empty_v2_Client(mac))                  # Put it in a list for consistency with parsing all clients
            elif CMXversions.Loc_api_version == "v3":
                CMXclient.append(Empty_v3_Client(mac))                  # Put it in a list for consistency with parsing all clients
        Add_CMXclient(CMXclient[0])                                     # Put the Client onto the InfectMacList
        Map_CMXclient(CMXclient[0])
        return(True)

    except:
        print("\n<<!>> CMX_loockup() -Fatal:  Error Executing Request:\tStatus: [",response.status_code,"]\tReason: [",response.reason,"]\n")
        CMXclient = []
        return(False)



# -------------------------------------------------------------------
# Empty_v2_Client() - If a client MAC is not found by CMX, I still need a "placeholder" for it.
#    This may not occur in real life, but in the sandboxes, you can sometimes get caught with no clients.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
def Empty_v2_Client(mac):
    
    if Debug:
        print("<<>> Empty_v2_Client() - Mac [", mac,"]")
    a2 = "Unknown"              # manufacturer - Always 'Lexmark' in CMX sandbox - This maybe valuable in the "real-world"
    a3 = "FEET"                 # map_unit - Units: 'FEET' in CMX sandbox
    a4 = 10.0                   # map_xcord - Client X-coordinate
    a5 = 10.0                   # map_ycord - Client Y-coordinate
    a6 = 10                     # mapinfo_height - Always '10'    in CMX sandbox
    a7 = 400                    # mapinfo_length - Always '400'   in CMX sandbox
    a8 = 0                      # mapinfo_offsetX - Always '0'    in CMX sandbox
    a9 = 4                      # mapinfo_offsetY - Always '4'    in CMX sandbox
    b1 = "FEET"                 # mapinfo_unit - Units: 'FEET' in CMX sandbox
    b2 = 400                    # mapinfo_width - Always '400'  in CMX sandbox
    b3 = '9876543210'           # mapinfo_floorRefId - Actually an INT/treat as a string now - 9 floors in CMX sandbox
    b4 = 1912                   # floorimage_height - Always '1912' in CMX sandbox
    b5 = 'unknownmap.jpg'       # floorimage_imageName - Always 'simfloor.jpg' in CMX sandbox
    b6 = 16                     # floorimage_maxRes - Always '16'   in CMX sandbox
    b7 = 3104                   # floorimage_size - Always '3104' in CMX sandbox
    b8 = 2801                   # floorimage_width - Always '2801' in CMX sandbox
    b9 = 5                      # floorimage_zoom - Always '5' in CMX sandbox
    c  = "OZone"                # mapHierarchy - 112 defined Zones in CMX sandbox

    CMXeClient = CMX_ClientLocation_v2(mac,a2,a3,a4,a5,a6,a7,a8,a9,b1,b2,b3,b4,b5,b6,b7,b8,b9,c)
    CMXeClient.Loc_Status         = "IoC"
    CMXeClient.currentServerTime  = "2019-02-25T04:17:16.311+0000"  # Current Server Time
    CMXeClient.firstLocateTime    = "2019-02-25T04:17:16.311+0000"  #
    CMXeClient.lastLocateTime     = "2019-02-25T04:17:16.311+0000"  #
    if Debug:
        print("<<>> Empty_v2_Client() - [", CMXeClient,"]")
    return(CMXeClient)


        
# -------------------------------------------------------------------
# Empty_v3_Client() - If a client MAC is not found by CMX, I still need a "placeholder" for it.
#    This may not occur in real life, but in the sandboxes, you can sometimes get caught with no clients.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
def Empty_v3_Client(mac):
    return([])



# -------------------------------------------------------------------
# Add_CMXclient() - This routine adds a CMX_Client to the InfectMacList and/or the QuarantineMacList.
#    (If it's found on a list it updates an existing entry for this MAC already on the list.  The
#    cmxClient structure comes from the CMX_lookup() routine.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
def Add_CMXclient(cmxClient):
    global InfectMacList, QuarantineMacList
    
    foundClient = False

    if Debug:
        print("<<>> Add_CMXclient() - Searching QuarantineMacList (",len(QuarantineMacList),") for [", cmxClient,"]")
    for i in range(len(QuarantineMacList)):             # Check the Quarantine list first
        if CMXversions.Loc_api_version == "v2":
            if cmxClient.macAddress == QuarantineMacList[i].macAddress:
                update_CMXclient(cmxClient,QuarantineMacList[i])
                foundClient = True
        elif CMXversions.Loc_api_version == "v3":
            if cmxClient.deviceId == QuarantineMacList[i].deviceId:
                update_CMXclient(cmxClient,QuarantineMacList[i])
                foundClient = True
        if foundClient:
            return(True)
    if Debug:
        print("<<>> Add_CMXclient() - Searching InfectMacList (",len(QuarantineMacList),") for [", cmxClient,"]")
    for i in range(len(InfectMacList)):                 # Client isn't quarantined, check the Infect list
        if CMXversions.Loc_api_version == "v2":
            if cmxClient.macAddress == InfectMacList[i].macAddress:
                update_v2CMXclient(cmxClient,QuarantineMacList[i])
                foundClient = True
        elif CMXversions.Loc_api_version == "v3":
            if cmxClient.deviceId == InfectMacList[i].deviceId:
                update_v3CMXclient(cmxClient,QuarantineMacList[i])
                foundClient = True
    if not foundClient:
        if Debug:
            print("<<>> Add_CMXclient() - Adding [",cmxClient,"] to InfectMacList")
        InfectMacList.append(copy.deepcopy(cmxClient))      # Add the Client to the InfectMacList
    return(True)



# -------------------------------------------------------------------
# update_v2CMXclient() - Once a MAC address is found and then queried again, update the old data with the new.
#    Not all data needs to be updated, but this will update most of the fields.  Then again, there maybe other
#    fields that could be updated later as well.  (Maybe we want to keep track of times.)
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
def update_v2CMXclient(newData,oldData):
    
    oldData.map_xcord            = newData.map_xcord
    oldData.map_ycord            = newData.map_ycord
    oldData.map_zcord            = newData.map_zcord
    oldData.mapinfo_height       = newData.mapinfo_height
    oldData.mapinfo_length       = newData.mapinfo_length
    oldData.mapinfo_offsetX      = newData.mapinfo_offsetX
    oldData.mapinfo_offsetY      = newData.mapinfo_offsetY
    oldData.mapinfo_unit         = newData.mapinfo_unit
    oldData.mapinfo_width        = newData.mapinfo_width
    oldData.mapinfo_floorRefId   = newData.mapinfo_floorRefId
    oldData.floorimage_height    = newData.floorimage_height
    oldData.floorimage_imageName = newData.floorimage_imageName
    oldData.floorimage_maxRes    = newData.floorimage_maxRes
    oldData.floorimage_size      = newData.floorimage_size
    oldData.floorimage_width     = newData.floorimage_width
    oldData.floorimage_zoom      = newData.floorimage_zoom
    oldData.mapHierarchy         = newData.mapHierarchy
    oldData.ipAddress            = newData.ipAddress
    oldData.networkStatus        = newData.networkStatus
    oldData.userName             = newData.userName
    oldData.currentServerTime    = newData.currentServerTime    # Current Server Time  [Add c1 variable to get live data here.] - v3 Client does not record this but has a "timestamp"g
    oldData.firstLocateTime      = newData.firstLocateTime      # First Time Client was Located  [Add c2 variable] - v3 Client does not record this
    oldData.lastLocateTime       = newData.lastLocateTime
    return()



# -------------------------------------------------------------------
# update_v3CMXclient() - Once a MAC address is found and then queried again, update the old data with the new.
#    Not all data needs to be updated, but this will update most of the fields.  Then again, there maybe other
#    fields that could be updated later as well.  (Maybe we want to keep track of times.)
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
def update_v3CMXclient(newData,oldData):
    oldData.locationMapHierarchy = newData.locationMapHierarchy         # Location Map Hierarchy
    oldData.locationCoordinateX  = newData.locationCoordinate-X         # client Location X-Coordinate
    oldData.locationCoordinateY  = newData.locationCoordinate-Y         # client Location Y-Coordinate
    oldData.locationCoordinateZ  = newData.locationCoordinate-Z         # client Location Z-Coordinate
    oldData.locationUnit         = newData.locationUnit                 # client Location Units
    oldData.geoCoordLat          = newData.geoCoordLat                  # Geocoordinate - Latitued
    oldData.geoCoordLong         = newData.geoCoordLong                 # Geocoordinate - Longitude
    oldData.geoCoordUnit         = newData.geoCoordUnit                 # Geocoordinate - Unit
    oldData.confidenceFactor     = newData.confidenceFactor             #
    oldData.userName             = newData.userName                     # CMX sancbox returns "" for all data.
    oldData.ipAddress            = newData.ipAddress                    # v3 Sandbox returns a list of addresses.
    oldData.floorRefId           = newData.floorRefId                   #
    oldData.lastSeen             = newData.lastSeen                     # Something like "2019-02-22T12:44:15.646+0000" 
    oldData.timestamp            = newData.timestamp                    # maybe current time?
    oldData.notificationTime     = newData.notificationTime             # Not sure what time this is.  Close to timestamp.
    return()
    


# -------------------------------------------------------------------
# Purge_CMXclient() - This routine removes a CMX_Client from the InfectMacList and/or the QuarantineMacList.
#    (Which ever list the Mac Address is found on.)  The cmxClient structure comes from the CMX_lookup() routine.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
def Purge_CMXclient(mac):
    global InfectMacList, QuarantineMacList
    DELmac = False

    if Debug:
        print("<<>> Purge_CMXclient() - [",len(InfectMacList),"]\t[",mac,"]")
    for i in range(len(InfectMacList)):
        if CMXversions.Loc_api_version == "v2":
            if InfectMacList[i].macAddress == mac:
                del InfectMacList[i]
                DELmac = True
                break
        elif CMXversions.Loc_api_version == "v3":
            if InfectMacList[i].deviceId == mac:
                del InfectMacList[i]
                DELmac = True
                break
    if not DELmac:
        for i in range(len(QuarantineMacList)):
            if CMXversions.Loc_api_version == "v2":
                if QuarantineMacList[i].macAddress == mac:
                    del QuarantineMacList[i]
                    DELmac = True
                    break
            elif CMXversions.Loc_api_version == "v3":
                if QuarantineMacList[i].deviceId == mac:
                    del QuarantineMacList[i]
                    DELmac = True
                    break
    if not DELmac:
        if Debug:
            print("<<>> Purge_CMXclient () - Infected MAC [",mac,"] not found in InfectMacList")


# -------------------------------------------------------------------
# Quarantine_CMXclient() - For now, this routine will move client Mac from the InfectMacList to the QuarantineMacList.
#    A call is made to CMX_lookup() to insure that the client is on the InfectMacList.  If they are already, it's no
#    problem, that will only update their information.  There is a status flag within the client structure that I could
#    change, but right now it's not used.  So there's really no need "now" to segregate the clients, unless you need to.
# NOTE:  I should clean up this routine.  The IOCmac tests are no longer needed after CMX_lookup() was added.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
def Quarantine_CMXclient(mac):
    global InfectMacList, QuarantineMacList
    
    IOCmac = False

    if Debug:
        print("<<>> Quarantine_CMXclient() - [",len(InfectMacList),"]\t[",mac,"]")
    for i in range(len(InfectMacList)):
        if CMXversions.Loc_api_version == "v2":
            if InfectMacList[i].macAddress == mac:
                QuarantineMacList.append(copy.deepcopy(InfectMacList[i]))
                del InfectMacList[i]
                IOCmac = True
                break
        elif CMXversions.Loc_api_version == "v3":
            if InfectMacList[i].deviceId == mac:
                QuarantineMacList.append(copy.deepcopy(InfectMacList[i]))
                del InfectMacList[i]
                IOCmac = True
                break
    if not IOCmac:                           # Legacy test.   This should not happen now that I call CMX_lookup() from the start.
        if Debug:
            print("<<>> Quarantine_CMXclient() - Infected MAC [",mac,"] not found in InfectMacList")
        CMX_lookup(mac)
        Quarantine_CMXclient(mac)
    return()


# -------------------------------------------------------------------
# Validate_Test() -  Validataion Testing of Modules. - This routine is verbose, and focuses on the Cisco Sandboxes.
#   NOTE:  I've noticed weird quirks with the Sandboxes.  There are times I run the code and no clients are found at all.
#          There are times when it says that there are large numbers of client devices, but no clients are found at all.
#      Answer: Run the program again, and generally it works the second time.  I have no idea why this occurs.
#   NOTE:  I regularly see that after quering the sandbox for clients, and it returns a valid list.  My next step is to
#          select a client MAC from that list and query for it.  It comes back that the client doesn't exist.  Once again
#          I see the pattern of failure, success, failure, success ... I have no idea why this occurs.  I want to blame
#          it on the sandbox, because the code works too.  (FYI, my best sandbox is in Asia.  Maybe a factor?)
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
def Validate_Test():
    global CMXversions, CMXclientList
    Verbose = False
    
    print ('Validate #1:  Identify CMXversion for  [{}]\tget_CMX_version()'.format(CMX["host"]))         # This call can be made without prior authentication.
    CMXversions = get_CMX_version(CMX["host"]) 
    if Verbose:
        print(CMXversions)                                                              # Verbose:   Versions will vary depending on the sandbox.
    else:
        print ("\t\tCMX Version is [{}]".format(CMXversions.Loc_api_version))
#    
    print("\nValidate #2:  Build CMX 'Headers'\tget_CMX_auth()")                       # Most CMX calls require this to be done first in my routines
    get_CMX_auth(CMX["username"],CMX["password"],CMX["Base64"])
    print("\t\t",CMXheaders,"\n")
#
    print ('Validate #3:  get_CMX_clientCount(CMX["host"])')    # This call must be made after authentication occurs
    CMXclientCount = get_CMX_clientCount(CMX["host"])
    print("\t\t",CMXclientCount,"\n")                                   # Number of clients will vary depending on the sandbox.
#
    print ('Validate #4:  get_CMX_MapsCounts(CMX["host"])')    # This call must be made after authentication occurs
    get_CMX_MapsCounts(CMX["host"])
    print("\t\tMapsCounts: ", MapsCounts,"\n")
#
    print ('Validate #5:  get_all_CMX_clients(CMX["host"])')    # This call builds a list of all CMX Clients currently in the system
    CMXclientList = get_all_CMX_clients(CMX["host"])
    print("\t\tNumber of Clients found: [",len(CMXclientList),"]\n")
#
    if len(CMXclientList) > 0:                                  # All the remaining tests require client Macs to work with.
        print('Validate #6:  CMX_lookup(mac) - Using MACs from full CMXclientList')         # This call queries CMX for a specific MAC address
        print('              Selecting Mac Addresses to the "InfectMacList" for this test:')   # The "CMX_lookup(mac)" routine is the normal entry into the CMX routines
        print("\t\tLooking up MAC's: [",CMXclientList[0].macAddress,",",CMXclientList[1].macAddress,",",CMXclientList[2].macAddress,",",CMXclientList[10].macAddress,",",
              CMXclientList[int(len(CMXclientList)/2)].macAddress,",",CMXclientList[int(len(CMXclientList)/3)].macAddress,",",CMXclientList[int(len(CMXclientList)/4)].macAddress,",",CMXclientList[int(len(CMXclientList)/5)].macAddress,"]")
        CMX_Client = CMX_lookup(CMXclientList[0].macAddress)
        CMX_Client = CMX_lookup(CMXclientList[1].macAddress)
        CMX_Client = CMX_lookup(CMXclientList[2].macAddress)
        CMX_Client = CMX_lookup(CMXclientList[10].macAddress)
        CMX_Client = CMX_lookup(CMXclientList[int(len(CMXclientList)/2)].macAddress) # I can't predict what the maximum clients is, so...
        CMX_Client = CMX_lookup(CMXclientList[int(len(CMXclientList)/3)].macAddress) # I can't predict what the maximum clients is, so...
        CMX_Client = CMX_lookup(CMXclientList[int(len(CMXclientList)/4)].macAddress) # I can't predict what the maximum clients is, so...
        CMX_Client = CMX_lookup(CMXclientList[int(len(CMXclientList)/5)].macAddress) # I can't predict what the maximum clients is, so...
        if Verbose:
            for i in range(len(InfectMacList)):
                print("IOCmac (",i,")\t",InfectMacList[i])
            print()
        else:
            print("\t\t[{}]\tMAC addresses currently on the InfectMacList\n".format(len(InfectMacList)))
#
        print('Validate #7:  CMX_quarintine(mac) - Moving some MACs from the InfectMacList to the CMXclientList')  
        print("\t\tMoving IOC MAC's: [",CMXclientList[0].macAddress,",",CMXclientList[1].macAddress,",",CMXclientList[2].macAddress,",",CMXclientList[15].macAddress,"]")
        print("\t\t[{}] is not currently on the InfectMacList.".format(CMXclientList[15].macAddress))      
        Quarantine_CMXclient(CMXclientList[0].macAddress)                     # Move a client previously inserted on the InfectMacList
        Quarantine_CMXclient(CMXclientList[1].macAddress)                     # Move a client previously inserted on the InfectMacList
        Quarantine_CMXclient(CMXclientList[2].macAddress)                     # Move a client previously inserted on the InfectMacList
        Quarantine_CMXclient(CMXclientList[15].macAddress)                    # This client isn't in the InfectMacList
        if Verbose:
            for i in range(len(InfectMacList)):
                print("IOCmac (",i,")\t",InfectMacList[i])
            for j in range(len(QuarantineMacList)):
                print("QuarantineMac (",j,")\t",QuarantineMacList[j])
        else:
            print("\t\t[{}]\tMAC addresses currently on the InfectMacList".format(len(InfectMacList)))
            print("\t\t[{}]\tMAC addresses currently on the QuarantineMacList\n".format(len(QuarantineMacList)))
#
        print('Validate #8:  CMX_purge(mac) - Removing MAC addresses from the InfectMacList and from the QuarantineMacList')
        print("\t\tRemoving MAC's from InfectMacList: [",CMXclientList[0].macAddress,",",CMXclientList[1].macAddress,",",CMXclientList[10].macAddress,",",CMXclientList[int(len(CMXclientList)/4)].macAddress,"]")
        print("\t\tRemoving MAC's from QuarantineMacList: [",CMXclientList[15].macAddress,", 00:01:02:03:aa:ff]")
        Purge_CMXclient(CMXclientList[0].macAddress)
        Purge_CMXclient(CMXclientList[1].macAddress)
        Purge_CMXclient(CMXclientList[10].macAddress)
        Purge_CMXclient(CMXclientList[int(len(CMXclientList)/4)].macAddress)
        Purge_CMXclient(CMXclientList[15].macAddress)                           # This client is on the QuarantineMacList
        Purge_CMXclient("00:01:02:03:aa:ff]")                                   # This client doesn't exist on any list.
        if Verbose:
            for i in range(len(InfectMacList)):
                print("IOCmac (",i,")\t",InfectMacList[i])
            for j in range(len(QuarantineMacList)):
                print("QuarantineMac (",j,")\t",QuarantineMacList[j])
        else:
            print("\t\t[{}]\tMAC addresses currently on the InfectMacList".format(len(InfectMacList)))
            print("\t\t[{}]\tMAC addresses currently on the QuarantineMacList\n".format(len(QuarantineMacList)))
    return()


                  
# -------------------------------------------------------------------
# main() -  Official start of the CMX modules is a call to CMX_Lookup(MACaddress).  The MACaddress is the MAC of a client with a detected IOC>
#           The client information from the API call will be placed int the InfectMacList.
#           If you chose to move that MAC to a QuarantineMacList to separate it from the other IOC macs, you can issue a second command
#           Quarantine_CMXclient(MACaddress).  
#           Finally, you can remove a client from either list using the Purge_CMXclient(MACaddress) command.
#   NOTE:  If you want to test these commands using the sandbox environment, you can use the Validate_Test() routine.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
#Validate_Test()         # Designed specifically for testing with multiple devnet / dCloud sandboxes.
#


