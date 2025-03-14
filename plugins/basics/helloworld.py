from octopwn.common.plugins import OctoPwnPluginBase


class OctoPwnPlugin(OctoPwnPluginBase):
	def __init__(self):
		OctoPwnPluginBase.__init__(self)
	
	async def run(self):
		await self.print('Hello, world!')