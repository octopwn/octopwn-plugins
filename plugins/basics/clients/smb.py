from octopwn.common.plugins import OctoPwnPluginBase
from octopwn.clients.smb.console import SMBClient
import typing

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

            # Create a SMB session, "sid" is the session ID which can be used to reference the session later
            sid, err = await self.octopwnobj.do_createclient('SMB', 'NTLM', cid, tid)
            if err is not None:
                raise err
            await self.print('SMB Session created')

            #retrieve the smb session we just created
            session = self.octopwnobj.sessions[sid]
            session = typing.cast(SMBClient, session)
            # perform a login
            _, err = await session.do_login()
            if err is not None:
                raise err
            await self.print('Login successful')

            # list shares
            _, err = await session.do_shares()
            if err is not None:
                raise err
            await self.print('Shares listed')
            
        except Exception as e:
            await self.print('Error: %s' % e)
