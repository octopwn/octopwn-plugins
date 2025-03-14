from octopwn.common.plugins import OctoPwnPluginBase
from octopwn.scanners.tcpportscanner import TCPPortScanner
import typing
import asyncio

# =====================================================================
# UNCREDENTIALED PORT SCANNING EXAMPLE
# =====================================================================
# This example demonstrates how to perform an uncredentialed port scan
# using the TCPPortScanner module in OctoPwn.

# SCANNER LIFECYCLE IN OCTOPWN
# ----------------------------
# 1. CREATE: Initialize a scanner object with do_createscanner()
# 2. CONFIGURE: Set scanner parameters with do_setparam()
# 3. EXECUTE: Start the scan with do_scan()
# 4. WAIT: Monitor completion with scan_running_evt
# 5. RETRIEVE: Get results with do_getlasthistory()

# CREATING A SCANNER
# ------------------
# Use octopwnobj.do_createscanner(scanner_type) to create a scanner
# This returns a session ID that references your scanner instance

# CONFIGURING PARAMETERS
# ---------------------
# Each scanner has required and optional parameters:
# - View available parameters: scanner.params.flatten()
# - Set parameters: scanner.do_setparam(param_name, param_value)
#
# Common parameter types:
# - str: Simple string values
# - strlist: Lists (set as comma-separated strings)
# - int: Integer values (converted to strings)
# - strbool: Boolean values ('1'/'True' or '0'/'False')
#
# Most scanners require at minimum:
# - targets: IP addresses/ranges to scan
# - credential: ID of stored credential (for credentialed scans only)

# EXECUTING AND MONITORING
# -----------------------
# - Start scan: scanner.do_scan()
# - Monitor: scanner.scan_running_evt.wait()
# - Cancel: scanner.do_stop()

# RETRIEVING RESULTS
# -----------------
# - Get last scan ID: scanner.do_getlasthistoryid()
# - Get results: scanner.do_getlasthistory()
# - Results are returned as a history entry object


class OctoPwnPlugin(OctoPwnPluginBase):
    def __init__(self):
        OctoPwnPluginBase.__init__(self)
    
    async def run(self):
        try:
            # Step 1: Create a TCP port scanner
            sid, err = await self.octopwnobj.do_createscanner('PORTSCAN')
            if err is not None:
                raise err
            await self.print('TCP Scanner created')

            # Get the scanner instance
            scanner = self.octopwnobj.sessions[sid]
            scanner = typing.cast(TCPPortScanner, scanner)

            # Step 2: Configure scanner parameters
            await scanner.do_setparam('targets', '192.168.56.0/24')
            await scanner.do_setparam('ports', '22,88,445')

            # Step 3: Execute the scan
            _, err = await scanner.do_scan()
            if err is not None:
                raise err
            await self.print('Scan started')

            # Step 4: Wait for scan completion (with timeout)
            await self.print('Waiting for scan to complete...')
            try:
                # Set a timeout to demonstrate how to handle long-running scans
                await asyncio.wait_for(scanner.scan_running_evt.wait(), timeout=5)
            except asyncio.TimeoutError:
                await self.print('Scan did not complete in time, stopping...')
                await scanner.do_stop()
                await self.print('Scan stopped')
            else:
                await self.print('Scan completed before timeout')
            
            # Step 5: Retrieve and process results
            
            # Get the history ID (useful for referencing specific scan results)
            history_id, err = await scanner.do_getlasthistoryid()
            if err is not None:
                raise err
            await self.print('History ID: %s' % history_id)

            # Get the scan results
            historyentry, err = await scanner.do_getlasthistory()
            if err is not None:
                raise err
            if historyentry is None:
                await self.print('No results found, there might be an error')
                return

            # Display scan parameters
            await self.print('Scan run parameters:')
            fparams = historyentry.parameters.flatten()
            for key, value in fparams.items():
                await self.print('%s: %s' % (key, value))

            # Display scan results
            await self.print('Scan results:')
            results = historyentry.results
            for result in results:
                await self.print(result)

        except Exception as e:
            await self.print('Error: %s' % e)
