from octopwn.common.plugins import OctoPwnPluginBase
from octopwn.clients.base import ClientConsoleBase
from octopwn.common.scanparams import ClientSessionParameters, ScanHistory
from octopwn.clients.smb.console import SMBClient
import typing

# ====================== SESSIONS IN OCTOPWN ======================
#
# What are sessions?
# ------------------
# In OctoPwn, a session represents any active component you're working with:
# - Clients: Used to connect to target systems (SMB, LDAP, WinRM, etc.)
# - Scanners: Used to perform security scans against targets
# - Utils: Utility tools for various operations
# - Servers: Services you can run to interact with targets
#
# Each session has a unique ID that allows you to reference it throughout your plugin.
#
# Creating Sessions
# ----------------
# You can create different types of sessions using these methods:
# - octopwnobj.do_createclient: Creates a client connection to a target
# - octopwnobj.do_createscanner: Creates a scanner for security testing
# - octopwnobj.do_createutil: Creates a utility tool
# - octopwnobj.do_createserver: Creates a server service
#
# Referencing Sessions
# -------------------
# Sessions are stored in the octopwnobj.sessions dictionary where:
# - Key: The session ID (a unique string identifier)
# - Value: The actual session object
#
# You can use the session ID to retrieve the session object later in your code.
# The session object provides methods and properties specific to its type.
#
# Session Properties
# -----------------
# All sessions have these common properties:
# - majortype: The main category (CLIENT, SCANNER, UTIL, SERVER)
# - subtype: The specific type within the category (e.g., SMB, LDAP)
# - params: Contains configuration parameters for the session
#
# This plugin demonstrates how to create an SMB client session and access its properties.

class OctoPwnPlugin(OctoPwnPluginBase):
    def __init__(self):
        OctoPwnPluginBase.__init__(self)
    
    async def run(self):
        try:
            # Add a target and credential
            tid, _, err = await self.octopwnobj.do_addtarget('192.168.56.11')
            if err is not None:
                raise err
            cid, _, err = await self.octopwnobj.do_addcred('NORTH\\hodor', 'hodor')
            if err is not None:
                raise err
            await self.print('Target and credential added')

            # Create a SMB client, "sid" is the session ID which can be used to reference the session later
            sid, err = await self.octopwnobj.do_createclient('SMB', 'NTLM', cid, tid)
            if err is not None:
                raise err
            await self.print('SMB Session created')

            # Print the sessions
            await self.print('Sessions:')
            for sid in self.octopwnobj.sessions:
                await self.print('Session ID: %s' % sid)
                session = self.octopwnobj.sessions[sid]
                majortype = session.majortype # This will be 'CLIENT'
                subtype = session.subtype # This will be 'SMB'
                params = session.params # This will be an object that contains the parameters for the session
                params = typing.cast(ClientSessionParameters, params)
                fparams = params.flatten() # This will be a dictionary of the parameters for the session
                await self.print('Major Type: %s' % majortype)
                await self.print('Subtype: %s' % subtype)
                await self.print('Params: %s' % fparams)
                await self.print('')
            
        except Exception as e:
            await self.print('Error: %s' % e)
