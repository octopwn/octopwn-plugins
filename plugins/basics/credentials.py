import asyncio
from octopwn.common.plugins import OctoPwnPluginBase
from octopwn.common.credential import Credential

# ===== CREDENTIALS IN OCTOPWN =====
#
# Credentials are fundamental building blocks in OctoPwn that store authentication information.
# They are used by clients, scanners, and other components throughout the framework.
#
# Key characteristics of credentials:
# 1. They typically store username/password pairs and related authentication data
# 2. They are IMMUTABLE - once created, they should not be modified (except for enrichment)
# 3. If you need to change a credential, create a new one instead
#
# Credentials are stored in octopwnobj.credentials dictionary:
# - Key: A unique string identifier (credential ID)
# - Value: The actual credential object
#
# This plugin demonstrates how to create and work with credentials in OctoPwn.


class OctoPwnPlugin(OctoPwnPluginBase):
    def __init__(self):
        OctoPwnPluginBase.__init__(self)
    
    async def run(self):
        try:
            # EXAMPLE: Creating a credential using the Credential object
            # This approach allows you to set all properties of the credential
            credobj = Credential(
                domain='NORTH',           # Domain for the credential
                username='hodor2',        # Username 
                secret='hodor2',          # The password or other secret
                stype='PASSWORD',         # Secret type (PASSWORD, NTLM, etc.)
                source='PLUGIN EXAMPLE',  # Where this credential came from
                description='Test credential for demonstration', # Human-readable description
                favorite=True,            # Mark as favorite for easy access
            )
            
            # Add the credential to OctoPwn's credential store
            # Returns: credential_id, error
            cid, err = await self.octopwnobj.addcredential_obj(credobj)
            if err is not None:
                raise err
            
            await self.print(f'Successfully added credential with ID: {cid}')
                
            # List all credentials in the system
            await self.print('\nAll credentials in the system:')
            for cid in self.octopwnobj.credentials:
                cred = self.octopwnobj.credentials[cid]
                await self.print(f'ID: {cid} | {cred.domain}\\{cred.username} | Source: {cred.source}')
        
        except Exception as e:
            await self.print(f'Error: {e}')
