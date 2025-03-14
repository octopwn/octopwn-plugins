from octopwn.common.plugins import OctoPwnPluginBase
from octopwn.scanners.tcpportscanner import TCPPortScanner
import typing

class OctoPwnPlugin(OctoPwnPluginBase):
    def __init__(self):
        OctoPwnPluginBase.__init__(self)
    
    async def run(self):
        try:
            # No need to add credential, this is an uncredentialed scan

            # Create a TCP scanner
            sid, err = await self.octopwnobj.do_createscanner('PORTSCAN')
            if err is not None:
                raise err
            await self.print('TCP Scanner created')

            #retrieve the scanner we just created
            scanner = self.octopwnobj.sessions[sid]
            scanner = typing.cast(TCPPortScanner, scanner)

            # setup all required parameters

            await scanner.do_setparam('targets', '192.168.56.0/24')
            await scanner.do_setparam('ports', '22,88,445')

            # perform a scan
            _, err = await scanner.do_scan()
            if err is not None:
                raise err
            await self.print('Scan started')

            # wait for the scan to complete
            await self.print('Waiting for scan to complete...')
            await scanner.scan_running_evt.wait()
            await self.print('Scan completed')

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
