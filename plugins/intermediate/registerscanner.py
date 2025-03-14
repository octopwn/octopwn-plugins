import asyncio
from octopwn.common.plugins import OctoPwnSessionRegisterPlugin

from octopwn.clients.scannerbase import ScannerConsoleBase
from octopwn.common.scanparams import InfoScanParameter, strlist, strbool, ScanParameter, ScanParameterCollection, CredentialedSMBScannerBaseParameters
from asysocks.unicomm.common.scanner.common import *




class OctoPwnPlugin(OctoPwnSessionRegisterPlugin):
    def __init__(self):
        # the 'UTIL' and 'EXAMPLEUTIL' are the major and minor type of the plugin. 
        # IMPORTANT: the same values MUST be used in the ScannerConsoleBase class,
        # otherwise the plugin will either overwrite another plugin or worse.
        OctoPwnSessionRegisterPlugin.__init__(self, 'SCANNER', 'EXAMPLESCANNER', ExampleScanner)


# the result class is used to store the results of the scanner.
# it is used to store the results of the scanner in a way that is easy to serialize and deserialize.
# it is also used to store the results of the scanner in a way that is easy to display in the GUI.
class ExampleScannerResult:
    def __init__(self, result1:str, result2:str):
        self.result1 = result1
        self.result2 = result2
    
    # The to_line method MUST be implemented.
    # the to_line method is used to convert the result to a SINGLE line of text.
    # this is used when the results are displayed in a table in the GUI or printed to the console
    def to_line(self, separator = '\t') -> str:
        return f'{self.result1}{separator}{self.result2}'
    
    # The to_dict method MUST be implemented.
    # the to_dict method is used to convert the result to a dictionary.
    # this is used when the scanner result is stored in a scan history or when the results are exported.
    # IMPORTANT: the keys MUST be strings, the values can be anything JSON serializable.
    def to_dict(self):
        return {
            'result1' : self.result1,
            'result2' : self.result2,
        }

# The Executor class is passed to the scanner core, and it's ``run`` method is called with the target and output queue.
# This class doesn't orchestrate the scanner, it's only responsible for performing action(s) against one target specified in the run method and creating the scanner result and putting it in the output queue.
# The executor MUST NOT raise an exception, if an error occurs during performing the scan's tasks it should put an error result in the output queue and return.
# Under the hood, the scanner core will limit the runtime of the executor, so you don't worry about timeouts but keep everything async.
class ExampleScannerExecutor:
    def __init__(self, factory):
        self.factory = factory

    # The run method MUST be implemented.
    # The run method is called with the target and output queue.
    # Do not change the signature of this method, it's used by the scanner core.
    async def run(self, targetid, target, out_queue):
        try:
            result1 = 'result1'
            result2 = 'result2'
            await out_queue.put(ScannerData(target, ExampleScannerResult(result1, result2)))
        except Exception as e:
            await out_queue.put(ScannerError(target, e))
            return

class ExampleScanner(ScannerConsoleBase):
    def __init__(self, projectid, client_id, connection, cmd_q, msg_queue, prompt, octopwnobj, params = None, history = None):
        default_params = ScanParameterCollection(
                CredentialedSMBScannerBaseParameters(
                    # the headers of the result table in the GUI. Note that the first column is the target which
                    # is not incorporated in the ExampleScannerResult, rather in the ScannerData object. `await out_queue.put(ScannerData(target,....`
                    resultheaders = ['SERVERIP', 'result1', 'result2'], 
                    # The info is optional, it's used to provide a description of the scanner.
                    info='Example scanner',
                ),
                # This is an example of a custom parameter this can be set with `self.params.setvalue('randomparam', 'newvalue')` and read with `self.params.getvalue('randomparam')`
                ScanParameter('randomparam', str, 'Random parameter', default='randomvalue', required=True, advanced=False),
            )
        ScannerConsoleBase.__init__(self, projectid,  'SCANNER', 'EXAMPLESCANNER', client_id, connection, cmd_q, msg_queue, prompt, octopwnobj, params, history, default_params=default_params)
        
        self.enumerator = None
        self.enumerator_task = None

    # The stop method is optional, it's used to perform any cleanup when the scanner is stopped.
    # This will be automatically called when the scanner is stopped with `do_stop()`.
    async def stop(self):
        try:
            if self.enumerator is not None:
                await self.enumerator.stop()
            if self.enumerator_task is not None:
                self.enumerator_task.cancel()
            return True, None
        except Exception as e:
            await self.print_exc(e)
            return None, e

    # this is the method which monitors the output queue and processes the results.
    # the name and signature of this method is irrelevant, it's up to you to decide what to do with the results.
    # It is highly recommended to use the `process_uniscan_result` method to process the result objects arriving.
    async def __monitor_queue(self, h_token = None, h_clientid = None):
        try:
            async for result in self.enumerator.scan():

                # if the task was cancelled, stop the scanner
                # this will make the code not throw an exception when the task is cancelled
                if asyncio.current_task().cancelled():
                    break
                
                # process the result with the built-in method. This will handle the result object and put it in the scan history.
                # the `h_token` and `h_clientid` are optional parameters that can be left out if not needed. If provided, the result will only be streamed to the client who started the scan.
                # If the scanner is using hostname/IP address (usually the case) then there will be a new target created for each address (or if the target already exists, it will be reused).
                # this will return the target id and an error if there was one.
                tid, err = await self.process_uniscan_result(result, h_token = h_token, h_clientid = h_clientid)
                if err is not None:
                    raise err

                # Feel free to do something with the target or the result here.
                # the result object contains a type which can be DATA, ERROR, INFO. 
                # The DATA type contains the result of the scan. The DATA type will have a `data` attribute which is one ScannerData ob.
                if result.type == ScannerResultType.DATA:
                    if result.data.result1 == 'result1':
                        await self.print(f'{result.target} - {result.data.result1} - {result.data.result2}')



            await self.do_stop(True)
            return True, None
        except asyncio.CancelledError:
            return True, None
        except Exception as e:
            await self.print_exc(e)
            return None, e

    async def scan(self, h_token = None, h_clientid = None):
        """Start enumeration"""
        try:
            factory, err = await self.create_credentialed_factory()
            if err is not None:
                raise err

            # create the executor
            executors = [ExampleScannerExecutor(factory)]

            self.enumerator, err = await self.create_credentialed_scanner(executors)
            if err is not None:
                raise err
            self.enumerator_task = asyncio.create_task(self.__monitor_queue(h_token, h_clientid))
            await self.print('[+] Scan started!')

            return True, None
        except Exception as e:
            await self.print_exc(e)
            return None, e
