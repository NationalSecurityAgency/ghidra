/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.plugin.core.debug.platform.arm;

import java.math.BigInteger;

import ghidra.app.plugin.core.debug.disassemble.*;
import ghidra.app.plugin.core.debug.disassemble.DisassemblyInjectInfo.PlatformInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.*;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.Msg;

@DisassemblyInjectInfo(
	platforms = {
		@PlatformInfo(langID = "ARM:LE:32:v8"),
		@PlatformInfo(langID = "ARM:LE:32:v8T"),
		@PlatformInfo(langID = "ARM:LEBE:32:v8LEInstruction"),
		@PlatformInfo(langID = "ARM:BE:32:v8"),
		@PlatformInfo(langID = "ARM:BE:32:v8T"),
		@PlatformInfo(langID = "ARM:LE:32:v7"),
		@PlatformInfo(langID = "ARM:LEBE:32:v7LEInstruction"),
		@PlatformInfo(langID = "ARM:BE:32:v7"),
		@PlatformInfo(langID = "ARM:LE:32:Cortex"),
		@PlatformInfo(langID = "ARM:BE:32:Cortex"),
		@PlatformInfo(langID = "ARM:LE:32:v6"),
		@PlatformInfo(langID = "ARM:BE:32:v6"),
		@PlatformInfo(langID = "ARM:LE:32:v5t"),
		@PlatformInfo(langID = "ARM:BE:32:v5t"),
		@PlatformInfo(langID = "ARM:LE:32:v5"),
		@PlatformInfo(langID = "ARM:BE:32:v5"),
		@PlatformInfo(langID = "ARM:LE:32:v4t"),
		@PlatformInfo(langID = "ARM:BE:32:v4t"),
		@PlatformInfo(langID = "ARM:LE:32:v4"),
		@PlatformInfo(langID = "ARM:BE:32:v4"),
	})
public class ArmDisassemblyInject implements DisassemblyInject {
	protected static final long THUMB_BIT = 0x20;

	protected boolean isThumbMode(RegisterValue cpsr) {
		return (cpsr.getUnsignedValue().longValue() & THUMB_BIT) != 0;
	}

	@Override
	public void pre(PluginTool tool, TraceDisassembleCommand command, TracePlatform platform,
			long snap, TraceThread thread, AddressSetView startSet, AddressSetView restricted) {
		/**
		 * TODO: There are probably several avenues to figure the TMode. The most important, I think
		 * is the cpsr register, when it's available. For auto-pc, the target ought to have recorded
		 * cpsr at the current snapshot.
		 */

		Language language = platform.getLanguage();
		Register cpsrReg = language.getRegister("cpsr");
		Register tModeReg = language.getRegister("TMode");

		if (cpsrReg == null || tModeReg == null) {
			Msg.error(this,
				"No cpsr or TMode register in ARM language?: " + language.getLanguageID());
			return;
		}

		TraceMemorySpace regs =
			platform.getTrace().getMemoryManager().getMemoryRegisterSpace(thread, false);
		/**
		 * Some variants (particularly Cortex-M) are missing cpsr. This seems to indicate it only
		 * supports THUMB. There is an epsr (xpsr in gdb), but we don't have it in our models, and
		 * its TMode bit must be set, or it will fault.
		 * 
		 * TODO: If registers are recorded as generic objects, then we can find epsr/xpsr whether or
		 * not its in the Sleigh model.
		 */
		if (regs == null || regs.getState(platform, snap, cpsrReg) != TraceMemoryState.KNOWN) {
			command.setInitialContext(new RegisterValue(tModeReg, BigInteger.ONE));
			return;
		}

		RegisterValue cpsrVal = regs.getValue(platform, snap, cpsrReg);
		if (isThumbMode(cpsrVal)) {
			command.setInitialContext(new RegisterValue(tModeReg, BigInteger.ONE));
		}
		else {
			command.setInitialContext(new RegisterValue(tModeReg, BigInteger.ZERO));
		}
	}
}
