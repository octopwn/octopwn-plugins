import asyncio
from octopwn.common.plugins import OctoPwnPluginBase
from octopwn.common.target import Target

"""
# Understanding Targets in OctoPwn

Targets are fundamental building blocks in OctoPwn that represent machines you're interacting with.

## Key Concepts:
- Targets store information about remote systems (IP addresses, hostnames, etc.)
- Targets are immutable once created (though they can be enriched with additional data)
- Targets are stored in `octopwnobj.targets` dictionary with unique IDs as keys

## Important Notes:
- Some protocols (like Kerberos) require FQDN hostnames, not just IP addresses
- When you provide both IP and hostname, OctoPwn will use the hostname when needed without DNS resolution
- Always use the provided methods to add targets, never modify the targets dictionary directly

## Methods for Creating Targets:
1. `do_addtarget()` - Simple method to add a target with basic information
2. `addtarget_obj()` - Add a pre-configured Target object with custom properties
3. `addtarget_obj_multi()` - Add multiple Target objects efficiently in one operation
"""

class OctoPwnPlugin(OctoPwnPluginBase):
    def __init__(self):
        OctoPwnPluginBase.__init__(self)
    
    async def run(self):
        try:
            # EXAMPLE 1: Creating a target using do_addtarget (simplest method)
            await self.print("=== Example 1: Basic target creation ===")
            tid, _, err = await self.octopwnobj.do_addtarget('192.168.56.11')
            if err is not None:
                raise err
            await self.print(f"Created target with ID: {tid}")

            # EXAMPLE 2: Creating a target with a Target object (more control)
            await self.print("\n=== Example 2: Creating target with hostname ===")
            targetobj = Target(ip='192.168.56.11', hostname='north.local')
            tid2, err = await self.octopwnobj.addtarget_obj(targetobj)
            if err is not None:
                raise err
            await self.print(f"Created target with ID: {tid2}")

            # EXAMPLE 3: Creating multiple targets at once (more efficient)
            await self.print("\n=== Example 3: Creating multiple targets at once ===")
            targetobj2 = Target(ip='192.168.56.12')
            targetobj3 = Target(ip='192.168.56.22')
            tids, err = await self.octopwnobj.addtarget_obj_multi([targetobj2, targetobj3])
            if err is not None:
                raise err
            await self.print(f"Created targets with IDs: {tids}")

            # Displaying all targets in the system
            await self.print("\n=== All Targets in System ===")
            for tid in self.octopwnobj.targets:
                target = self.octopwnobj.targets[tid]
                await self.print(f"Target ID: {tid}")
                await self.print(f"  {target}")
                await self.print("")
        
        except Exception as e:
            await self.print(f'Error: {e}')
