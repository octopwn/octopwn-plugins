from octopwn.common.plugins import OctoPwnPluginBase
from octopwn.scanners.smbadmin import SMBAdminScanner
import typing
import asyncio

class OctoPwnPlugin(OctoPwnPluginBase):
    def __init__(self):
        OctoPwnPluginBase.__init__(self)
    
    async def run(self):
        try:
            # SMBAdmin scanner is a credentialed scanner,
            # so we need to add a credential
            cid, _, err = await self.octopwnobj.do_addcred('NORTH\\hodor', 'hodor')
            if err is not None:
                raise err
            await self.print('Credential added')

            # Create a TCP scanner
            sid, err = await self.octopwnobj.do_createscanner('SMBADMIN')
            if err is not None:
                raise err
            await self.print('SMB Admin Scanner created')

            #retrieve the scanner we just created
            scanner = self.octopwnobj.sessions[sid]
            scanner = typing.cast(SMBAdminScanner, scanner)

            # setup all required parameters

            await scanner.do_setparam('targets', '192.168.56.0/24')
            # set the credential ID for the scanner to be used during authentication
            await scanner.do_setparam('credential', str(cid)) 

            # perform a scan
            _, err = await scanner.do_scan()
            if err is not None:
                raise err
            await self.print('Scan started')

            # for an example, we do not wait until the scan is complete
            # rather wait a set amount of time, and then stop the scan
            await self.print('Waiting for scan to complete...')
            try:
                await asyncio.wait_for(scanner.scan_running_evt.wait(), timeout=5)
            except asyncio.TimeoutError:
                await self.print('Scan did not complete in time, stopping...')
                await scanner.do_stop()
                await self.print('Scan stopped')
            else:
                await self.print('Scan completed before timeout')
            
            # just because the scan has been interrupted, we still can retrieve 
            # the intermediate results the same way as if the scan has been completed

            # get the History ID of the last scan run
            # It is not needed in the current example, 
            # but it is useful if you want to get the results of a specific scan
            history_id, err = await scanner.do_getlasthistoryid()
            if err is not None:
                raise err
            await self.print('History ID: %s' % history_id)

            # get the latest scan results
            historyentry, err = await scanner.do_getlasthistory()
            if err is not None:
                raise err
            if historyentry is None:
                await self.print('No results found, there might be an error')
                return

            # print the scan run parameters
            # not necessary needed to get the results
            # but useful to know what was scanned
            await self.print('Scan run parameters:')
            fparams = historyentry.parameters.flatten()
            for key, value in fparams.items():
                await self.print('%s: %s' % (key, value))

            # print the scan results
            await self.print('Scan results:')
            results = historyentry.results
            for result in results:
                await self.print(result)

        except Exception as e:
            await self.print('Error: %s' % e)
