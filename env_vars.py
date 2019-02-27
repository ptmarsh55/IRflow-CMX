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

#This file contains environment variables for my Cisco API programs.  In some cases
#  the information below can be personal, and should not be shared with others.  If so,
#  remove all username, password and Base64 information prior to shaing this file.
#  In this case, I am using sandboxes that are publically available and require Cisco
#  credentials to get access.

# To get login credentials, go to the following URL.  Login with your Cisco credentials,
#   and search for CMX.  The credentials are in the Instant demo documentation
# https://dcloud.cisco.com/
dCloud_cmx_sandbox = {
    "host":  "dcloud-dna-cmx-sjc.cisco.com",
    "username": "amdemo1",
    "password": "C1sco12345",
    "Base64":   "YW1kZW1vMTpDMXNjbzEyMzQ1"
}

# Asia PAC dCloud sandbox
dCloud_apac_cmx_sandbox = {
    "host":  "dcloud-dna-cmx-lon.cisco.com",
    "username": "amdemo1",
    "password": "C1sco12345",
    "Base64":   "YW1kZW1vMTpDMXNjbzEyMzQ1"
}

# To get login credentials, go to the following URL and login with your Cisco credentials.
# https://developer.cisco.com/site/sandbox/
Devnet_cmx_sandbox = {
    "host": "cmxlocationsandbox.cisco.com",
    "username": "learning",
    "password": "learning",
    "Base64":   "bGVhcm5pbmc6bGVhcm5pbmc="
}

# File paths to specific files
TinyLoc     = "C:/Users/pmarsh/My Documents/Python/IRFlow/TinyDB/"
ImageLoc    = "C:/Users/pmarsh/My Documents/Python/IRFlow/Images/"

# Dictionary of Threat Icon filenames by color - These icons are 20x20 pixles
ThreatIcons = {'Black':{'bio':'bioBlack.jpg',   # Black BioHazard 
    'poi':'poiBlack.jpg',                   # Black Poison
    'rad':'radBlack.jpg',                   # Black Radiation
    'shk':'shkBlack.jpg'},                  # Black Shock
    'Red':{'bio':'bioRed.jpg',              # Red BioHazard
    'poi':'poiRed.jpg',                     # Red Poison
    'rad':'radRed.jpg',                     # Red Radiation
    'shk':'shkRed.jpg'},                    # Red Shock
    'Yellow':{'bio':'bioYellow.jpg',        # Yellow BioHazard
    'poi':'poiYellow.jpg',                  # Yellow Poison
    'rad':'radYellow.jpg',                  # Yellow Radiation
    'shk':'shkYellow.jpg'}}                 # Yellow Shock

# Dictionary of Dot Colors - These icons are 9x9 pixles
DotIcons = {'Black':'BlackDot.png',         # All Black Dot
    'BlkBl':'BlackBlueDot.png',             # Black + Blue Center
    'BlkWh':'BlackWhiteDot.png',            # Black + White Center
    'BlkYl':'BlackYellowDot.png',           # Black + Yellow Center
    'Blue':'BlueDot.png',                   # All Blue Dot
    'BluGr':'BlueGrayDot.png',              # Blue + Gray Center
    'BluGn':'BlueGreenDot.png',             # Blue + Green Center
    'Brick':'BrickRdDot.png',               # All Brick Red DOt
    'BrikO':'BrickRdOrDot.png',             # Brick Red + Orange Center
    'Brown':'BrownDot.png',                 # All Brown Dot
    'Gray':'GrayDot.png',                   # All Gray Dot
    'Green':'GreenDot.png',                 # All Green Dot
    'GrnOr':'GreenOrangeDot.png',           # Green + Orange Center
    'GrnYl':'GreenYellowDot.png',           # Green + Yellow Center
    'LtBlu':'LtBlueDot.png',                # All Lite Blue Dot
    'Orang':'OrangeDot.png',                # All Orange Dot
    'Purpl':'PurpleDot.png',                # All Purple Dot
    'PurBl':'PurpleBlueDot.png',            # Purple + Blue Center
    'PurYl':'PurpleYellowDot.png',          # Purple + Yellow Center
    'Red':'RedDot.png',                     # All Red Dot
    'RedBk':'RedBlackDot.png',              # Red + Black Center
    'RedWh':'RedWhiteDot.png'}              # Red + White Center

