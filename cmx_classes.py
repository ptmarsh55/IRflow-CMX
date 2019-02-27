'''
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

# cmx_classes() - defines a number of CMX classes that are used with the CMX API calls.  
#   - There will be one CMX class for each API call used.  (Defined in the comment by the class statement.)
#   - Each class may contain ALL the fields returned by the CMX API call.  If all fields are not included, it will be noted.
#   - In some cases I will add additional information to the class in order to stitch data from our various sandboxes together.
#   - Those elements are defined by the '<<>>' comments are in addition to the data provided by the API call
#   - Each class has a print statement for diagnostics, based on the information we use in our application

# -------------------------------------------------------------------
# CMX_ClientLocation - "/api/location/v2/clients"
#   The CMX_ClientLocation Class contains a subset of the data returned by the given API call.
#   Contains only those fields returned by the API call relating to Client Locations.  In addition, I've added 2 fields.
#   - IFRmac maps a client MAC seen on CMX to one seen as infected.  This is only necessary because we need to stitch the two
#     systems together.  In real life this would not be necessary.
#   - Timestamp is updated each time we pull data about this CMX client from CMX
#   Other Fields missing from this API call include the following:  (Many will contain valuable data in a live system.)
#   - "areaGlobalIdList"; "band"; "bytesReceived"; "bytesSent"; "changedOn"; "confidenceFactor"; "currentlyTracked"; "detectingControllers"; "dot11Status"; "geoCoordinate"; "guestUser"; "historyLogReason"
#   - "mapCoordinate.z"; "image.colorDepth"; "tagList"; "Regular Layout",; "Flagship",; "IL",; "Restricted WiFi Access"; "rawLocation"; "rawX"; "rawY"; "unit"; "sourceTimestamp"
#   - "ssId"; "statistics"; "currentServerTime"; "firstLocatedTime"; "lastLocatedTime"; "maxDetectedRssi"; "antennaIndex"; "apMacAddress"; "band"; "lastHeardInSeconds"; "rssi"; "slot"
#   I have added some of the fields that are basically static on the CMX sandbox, but could easily include them on a live system.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
class CMX_ClientLocation_v2:				# "/api/location/v2/clients"
    def __init__ (self,a1,a2,a3,a4,a5,a6,a7,a8,a9,b1,b2,b3,b4,b5,b6,b7,b8,b9,c):
        self.Loc_IRFmac      = '00:00:00:00:00:00'      # <<>> Not part of CMX data. Used to map to IRFlow Mac address <<>>
        self.Loc_time        = "NoTime"                 # <<>> Not part of CMX data. Used to hold current time of the API call <<>>
        self.Loc_Status      = "OnNet"					# <<>> Not part of CMX data. Used to identify the status of the client [OnNet, OffNet, Quarantined] <<>>
        self.macAddress      = str(a1)                  # Sandbox MACs are somewhat sequential, but can occur multiple times in CMX sandbox
        self.manufacturer    = str(a2)                  # Always 'Lexmark' in CMX sandbox - This maybe valuable in the "real-world"
        self.map_unit        = str(a3)                  # Units: 'FEET' in CMX sandbox
        self.map_xcord       = float(a4)                # Client X-coordinate
        self.map_ycord       = float(a5)                # Client Y-coordinate
        self.map_zcord       = 0                        # Always zero   Client Z-coordinate
        self.mapinfo_height  = int(a6)                  # Always '10'   in CMX sandbox
        self.mapinfo_length  = int(a7)                  # Always '400'  in CMX sandbox
        self.mapinfo_offsetX = int(a8)                  # Always '0'    in CMX sandbox
        self.mapinfo_offsetY = int(a9)                  # Always '4'    in CMX sandbox
        self.mapinfo_unit    = str(b1)                  # Units: 'FEET' in CMX sandbox
        self.mapinfo_width   = int(b2)                  # Always '400'  in CMX sandbox
        self.mapinfo_floorRefId   = str(b3)             # Actually an INT/treat as a string now - 9 floors in CMX sandbox
        self.floorimage_height    = int(b4)             # Always '1912' in CMX sandbox
        self.floorimage_imageName = str(b5)             # Always 'simfloor.jpg' in CMX sandbox - (can't access image via API in sandbox)
        self.floorimage_maxRes    = int(b6)             # Always '16'   in CMX sandbox
        self.floorimage_size      = int(b7)             # Always '3104' in CMX sandbox
        self.floorimage_width     = int(b8)             # Always '2801' in CMX sandbox
        self.floorimage_zoom      = int(b9)             # Always '5'    in CMX sandbox
        self.mapHierarchy         = str(c)              # 112 defined Zones in CMX sandbox
        self.ipAddress            = "0.0.0.0"           # CMX sandbox returns "null" for all data. Will deal with this on a live system later.
        self.networkStatus        = "ACTIVE"            # CMX sancbox returns "ACTIVE" for all data.
        self.userName             = "NoName"            # CMX sancbox returns "" for all data.
        self.currentServerTime    = "2019-02-25T04:17:16.311+0000"  # Current Server Time  [Add c1 variable to get live data here.] - v3 Client does not record this but has a "timestamp"g
        self.firstLocateTime      = "2019-02-25T04:03:38.397+0000"  # First Time Client was Located  [Add c2 variable] - v3 Client does not record this
        self.lastLocateTime       = "2019-02-25T04:17:14.009+0000"  # Last Time Client was Located   [Add c3 variable] - v3 Client shows this
    def __str__(self):
        return("["+self.Loc_IRFmac+"] ["+self.macAddress+"\t"+self.ipAddress+"\t"+self.manufacturer+"\t"+self.mapinfo_floorRefId+"\t"+str(self.map_xcord)+"\t"+str(self.map_ycord)+"\t"+self.mapHierarchy+"]")

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
class CMX_ClientLocation_v3:			    # "/api/location/v3/clients"
    def __init__ (self,a1,a2,a3,a4,a5,a6,a7,a8,a9,b1,b2,b3,b4,b5,b6):
        self.Loc_Status           = "OnNet"				# <<>> Not part of CMX data. Used to identify the status of the client [OnNet, OffNet, Quarantined] <<>>
        self.locationMapHierarchy = str(a1)             # Location Map Hierarchy
        self.locationCoordinateX  = str(a2)             # client Location X-Coordinate
        self.locationCoordinateY  = str(a3)             # client Location Y-Coordinate
        self.locationCoordinateZ  = str(a4)             # client Location Z-Coordinate
        self.locationUnit         = str(a5)             # client Location Units
        self.geoCoordLat          = float(a6)           # Geocoordinate - Latitued
        self.geoCoordLong         = float(a7)           # Geocoordinate - Longitude
        self.geoCoordUnit         = str(a8)             # Geocoordinate - Unit
        self.confidenceFactor     = int(a9)             #
        self.userName             = "NoName"            # CMX sancbox returns "" for all data.
        self.ipAddress            = []                  # v3 Sandbox returns a list of addresses.
        self.floorRefId           = int(b1)             #
        self.deviceId             = str(b2)             # Same as macAddress in v2 (I think) 
        self.lastSeen             = str(b3)             # Something like "2019-02-22T12:44:15.646+0000" 
        self.manufacturer         = str(b4)             # Always
        self.timestamp            = int(b5)             # maybe current time?
        self.notificationTime     = int(b6)             # Not sure what time this is.  Close to timestamp.
        
    def __str__(self):
        return("["+self.deviceId+"\t"+self.ipAddress+"\t"+self.manufacturer+"]")
        
        
# -------------------------------------------------------------------
# CMX_ClientCount - "/api/location/v2/clients/count" - NOTICE: This call has been Deprecated.
#   Contains All fields returned by the API call, with an additional TimeStamp & apiVersion that I added.
#   I don't think I'll use this one, but adjust my output and use the CMX_ClientCount version.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
class CMX_v2ClientCount:                                # "/api/location/v3/clients/count"
    def __init__ (self,dtype,dquer,count):
        self.Loc_time           = "NoTime"              # <<>> Not part of CMX data, but used to hold current time of the API call <<>> 
        self.Loc_apiVersion     = "v2"                  # <<>> Not part of CMX data. Identifies the version of this call. 
        self.deviceType         = str(dtype)            # Not sure of the value of this 'Wireless_Client' 
        self.deviceQueryString	= str(dquer)            # Not sure of the value of this 'None'
        self.count              = int(count)            # Total Count of Client Devices seen
    def __str__(self):
        return("API Version: ["+self.apiVersion+"]\tClient Count: ["+self.count+"]")
    

# -------------------------------------------------------------------
# CMX_ClientCount - "/api/location/v3/clients/count"
#   Contains All fields returned by the API call, with an additional TimeStamp& apiVersion that I added.
#   SEE: Notes in CMX_v2ClientCount class.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
class CMX_ClientCount:                                  # "/api/location/v3/clients/count"
    def __init__ (self,total,assoc,probe):
        self.Loc_time        	= "NoTime"              # <<>> Not part of CMX data, but used to hold current time of the API call <<>> 
        self.Loc_apiVersion  	= "v3"                  # <<>> Not part of CMX data. Identifies the version of this call. 
        self.associatedCount 	= int(assoc)            # Count of Associated Client Devices
        self.probingCount    	= int(probe)            # Count of Probing Client Devicess seen
        self.totalCount      	= int(total)            # Total Count of Client Devices seen
    def __str__(self):
        return("API Version: ["+self.Loc_apiVersion+"]\tTotal Client Devices: ["+str(self.totalCount)+"]\tAssociated Clients: ["+str(self.associatedCount)+"]\tProbing Devices: ["+str(self.probingCount)+"]")
    

# -------------------------------------------------------------------
# CMX_version - "/api/config/v1/version/image"
#   Contains All fields returned by the API call, with an additional TimeStamp that I added.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
class CMX_version:                                      # "/api/config/v1/version/image"
    def __init__ (self,ver,conn,wips,cmx):
        self.Loc_api_version	= "v3"                  # <<>> Not part of CMX data. Identify if v2 or v3 calls should be used.  (default is v3)
        self.image_version   	= str(ver)              # 
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
        self.cmx_connect     	= str(conn)             #
        self.cmx_wips        	= str(wips)             #
        self.cisco_cmx       	= str(cmx)              #
    def __str__(self):
        return("CMX Image Versions: "+self.image_version+"\tCMX Connect: "+self.cmx_connect+"\tCMX WIPS: "+self.cmx_wips+"\tCisco CMX: "+self.cisco_cmx)


# -------------------------------------------------------------------
# CMX_MapsCount - "/api/config/v1/maps/count"
#   Contains a hierarchy of the Campuses, Buindings, Floors and AP's on each floor.  This can be quite extensive based on your deployment.
#   Given the complexity of this hierarchy, there are actually 3 classes related to this single class.  They are highlighted below.
#       The "campusCounts" field is a list of Class:  CampusCounts.
#           The "buildingCounts" field is a list of Class: BuildingCounts.
#               The "floorCounts" field is a list of Class:  FloorCounts. 
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
class CMX_MapsCount:                                    # "/api/config/v1/maps/count"
    def __init__ (self,tc,tb,tf,ta):
        self.totalCampuses  	= int(tc)               # Total Campuses
        self.totalBuildings   	= int(tb)               # Total Buildings
        self.totalFloors     	= int(tf)               # Total Floors
        self.totalAps        	= int(ta)               # Total AP's
        self.campusCounts       = []                    # List of Campuses which in turn has lists of Buildings & lists of Floors
    def __str__(self):
        return("Total Campuses: "+str(self.totalCampuses)+"\tTotal Buildings: "+str(self.totalBuildings)+"\tTotal Floors: "+str(self.totalFloors)+"\t\tTotal AP's: "+str(self.totalAps))

# -------------------------------------------------------------------
# CampusCounts - This class supports the CMX_MapsCount API call.  See:  "/api/config/v1/maps/count"
#   This Class contains info for one Campus on your infrastructure, with pointers to Buildings within each campus.  [Which in turn has pointers to floors in
#   those buildings and a count of AP's on each floor.  The "buildingCounts" field is a list of Class:  BuildingCounts.
#   [See Class:  CMX_MapsCount]
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
class CampusCounts:                                     # 
    def __init__ (self,cn,tb):
        self.campusName  	    = str(cn)               # Campus Name
        self.totalBuildings   	= int(tb)               # Total Buildings on that campus
        self.buildingCounts     = []                    # List of Buildings which in turn has lists of Floors
    def __str__(self):
        return("Campus Name: "+self.campusName+"\tTotal Buildings: "+str(self.totalBuildings))

# -------------------------------------------------------------------
# BuildingCounts - This class supports the CMX_MapsCount API call.  See:  "/api/config/v1/maps/count"
#   This Class contains info for one building on your infrastructure, with pointers to Floors within each building.
#   [See Class:  CampusCounts]  The "floorCounts" field is a list of Class:  FloorCounts.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
class BuildingCounts:                                   # 
    def __init__ (self,bn,tf):
        self.buildingName  	    = str(bn)               # Building Name
        self.totalFloors    	= int(tf)               # Total Floors in that Buildings
        self.floorCounts        = []                    # List of Floors which in turn has a count of AP's on that floor
    def __str__(self):
        return("\tBuilding Name: "+self.buildingName+"\tTotal Floors: "+str(self.totalFloors))

# -------------------------------------------------------------------
# BuildingCounts - This class supports the CMX_MapsCount API call.  See:  "/api/config/v1/maps/count"
#   This Class contains info for one floor in a building on your infrastructure.
#   [See Class:  BuildingCounts]
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
class FloorCounts:                                      # 
    def __init__ (self,fn,ap):
        self.floorName  	    = str(fn)               # Floor Name
        self.apCounts           = int(ap)               # Count of AP's on that floor
    def __str__(self):
        return("\t\tFloor Name: "+self.floorName+"\tTotal AP's: "+str(self.apCounts))
