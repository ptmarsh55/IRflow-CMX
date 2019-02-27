# IRflow-CMX
CMX Modules for IRflow Project

This repositoryt contains a series of routines to locate clients with IOCs (by MAC address), and create an image showing the
location of that MAC address.  Development was done primarily on CMX with v2 API calls.  Later I started adding code to support
CMX v3 API calls, but I didn't have a v3 server that consistently provided me with data.  Within the code you will see tests in
many routines like [if CMXversions.Loc_api_version == "v2":].  These are the begining of my support for v3 calls, but as a whole,
this program does not support v3 API's.  This is left to the reader.

You may see a few modules that are not directly required by the IRflow project.  You can weed those out if you want to, but since
they're not "called", they can be used for additional features as needed.

Useage:   
    Modify the env_vars.py file with your own credentials.  You will need to import that into the main program as "CMX".  For testing,
    I've used a couple different publically accessible sandbox systems.  Both are listed in this file, and can be toggled by selecting
    one verses the other within the CMX-Modules.py file.  (i.e.)
    
    #from env_vars import Devnet_cmx_sandbox as CMX		# CMX (Devnet) locations Sandbox. v3 data but it returns empty API results
    from env_vars import dCloud_apac_cmx_sandbox as CMX     # CMX APAC Sandbox.   v2 data but it returns API results
    
    There is no "main()" program per-se for these routines.  You simply need to call the CMX_lookup() routine to get your client
    added to the InfectMacList and to generate an image of their location.  The three external-facing routines you maybe interested
    in are as follows.
     
    CMX_lookup(mac) - Queries CMX for the MAC address, adds the client to the "InfectMacList" and produces a map of the client location.
                      Any subsiquent calls to this routine will query CMX for a current location and re-write the client info an
                      produce a new location map.
    Quarantine_CMXclient() - This routine moves a client on the "InfectMacList" to the "QuarantineMacList".  We don't currently include
                      an application for this, but maybe you will.  It is also another way to get a client into the system.  If the client
                      isn't currently present on the "InfectMacList", (from a prior CMX_lookup() can call), this routine will call
                      CMX_lookup(), and then moves the client directly onto the "QuarantineMacList".
    Purge_CMXclient() - Searches the "InfectMacList" and the "QuarantineMacList" for the Mac address and removes it from either list.
    
    You don't have modify the cmx_classes file, but they are imported.  This file contains Class structures for the various API calls I've
    set up for CMX.  Not all API fields are included in each corresponding class, and sometimes I added some "Local" fields to assist in
    the development of this project, but probably wouldn't be needed in a production mode.  Each class has a "print" function as well, that
    maybe useful.
    
Caveats:
    -  You need to download the floor maps manually at this time.  The name of those images must map those found in the "floorinfo" --> 
       "imageName" field in the v2 "/api/location/v2/clients".   (This requires more steps in v3 API.)   If a floor image doesn't exist,
       the client location is imposed on a blank template.
    -  If a MAC address is not found in CMX, a default structure for that client will be created.  The location of that client will be 
       placed in the upper-left corner of the blank floor template.

Testing:
    For test purposes, I've included a "Validate()" script, which acts as a main() program for testing these modules.
    -  I've noticed that the test sandboxes will sometimes not provide data.  If that's the case, simply re-run the program.
