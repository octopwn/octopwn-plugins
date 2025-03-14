
from octopwn.common.plugins import OctoPwnSessionRegisterPlugin

from octopwn.clients.scannerbase import ScannerConsoleBase
from octopwn.common.scanparams import InfoScanParameter, strlist, strbool, ScanParameter, ScanParameterCollection, CredentialedSMBScannerBaseParameters




class OctoPwnPlugin(OctoPwnSessionRegisterPlugin):
    def __init__(self):
        # the 'UTIL' and 'EXAMPLEUTIL' are the major and minor type of the plugin. 
        # IMPORTANT: the same values MUST be used in the ScannerConsoleBase class,
        # otherwise the plugin will either overwrite another plugin or worse.
        OctoPwnSessionRegisterPlugin.__init__(self, 'UTIL', 'EXAMPLEUTIL', ExampleUtil) 


class ExampleUtil(ScannerConsoleBase):
	def __init__(self, projectid, client_id, connection, cmd_q, msg_queue, prompt, octopwnobj, params = None, history = None):
        # default_params is a collection of parameters that provide a persistent way to store parameters between restarts.
        # the parameters are stored in the octopwn.session file and reload automatically when octopwn is restarted.
        # the parameter values can be changed at runtime by the user same way as the scanner parameters. (they are the same object and follow the same rules)
		default_params = ScanParameterCollection()

		ScannerConsoleBase.__init__(self, projectid,  'UTIL', 'EXAMPLEUTIL', client_id, connection, cmd_q, msg_queue, prompt, octopwnobj, params, history, default_params=default_params)

        # the nologon_commands is a list of commands that will not be allowed until the self.login_ok is set to True.
        # the 'any' means that ALL commands are allowed without login, as this is a utility plugin login is not required.
		self.nologon_commands.append('any')

        # the help_groups is a dictionary that defines the help groups for the plugin.
        # the '__skip' group is a special group that is used to ommit the commands listed in the group from the help output.
        # the 'EXAMPLECMDGROUP' is a group that contains the 'examplecmd' command, it must be defined without the 'do_' prefix.
        # the 'examplecmd' command is a command that prints the command given to it.
        # you can leave this empty if you don't want to define any help, BUT in case you define any help the commands listed there 
        # must be present in the class otherwise it will fail during load time.
		self.help_groups['COMMANDS'] = {
			'__skip': {'start': 0, 'stop': 0, 'scan': 0},
			'EXAMPLECMDGROUP' : {'examplecmd':0,},
		}
	
    # the do_<command> functions are the commands that the users can interact with from the GUI.
    # you can define commands without the "do_" prefix, but those commands will only be available 
    # via the API, and those commands MUST NOT be listed in the help_groups.
    # It is highly recommended that every command returns a tuple with two values:
    # - The first value can be anything JSON serializable
    # - The second value is an optional exception object or None if the command is successful.
    # If an error occurs it is highly recommended to print the error to the console using the self.print_exc() function.

    # The """docstring""" is the help text that will be displayed to the user when they request help for the command.
	async def do_examplecmd(self, cmd:str):
		"""This is an example command that prints the command given to it"""
		try:
			await self.print(f"Command received: {cmd}")
			return True, None
		except Exception as e:
			await self.print_exc(e)
			return None, e