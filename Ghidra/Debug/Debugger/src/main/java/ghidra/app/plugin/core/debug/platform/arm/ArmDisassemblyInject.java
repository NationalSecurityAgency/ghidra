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

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.core.debug.workflow.DisassemblyInject;
import ghidra.app.plugin.core.debug.workflow.DisassemblyInjectInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.trace.model.memory.TraceMemoryRegisterSpace;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.Msg;

@DisassemblyInjectInfo(
	langIDs = {
		"ARM:LE:32:v8",
		"ARM:LE:32:v8T",
		"ARM:LEBE:32:v8LEInstruction",
		"ARM:BE:32:v8",
		"ARM:BE:32:v8T",
		"ARM:LE:32:v7",
		"ARM:LEBE:32:v7LEInstruction",
		"ARM:BE:32:v7",
		"ARM:LE:32:Cortex",
		"ARM:BE:32:Cortex",
		"ARM:LE:32:v6",
		"ARM:BE:32:v6",
		"ARM:LE:32:v5t",
		"ARM:BE:32:v5t",
		"ARM:LE:32:v5",
		"ARM:BE:32:v5",
		"ARM:LE:32:v4t",
		"ARM:BE:32:v4t",
		"ARM:LE:32:v4",
		"ARM:BE:32:v4",
	})
public class ArmDisassemblyInject implements DisassemblyInject {
	protected static final long THUMB_BIT = 0x20;

	protected boolean isThumbMode(RegisterValue cpsr) {
		return (cpsr.getUnsignedValue().longValue() & THUMB_BIT) != 0;
	}

	@Override
	public void pre(PluginTool tool, DisassembleCommand command, TraceProgramView view,
			TraceThread thread, AddressSetView startSet, AddressSetView restricted) {
		/**
		 * TODO: There are probably several avenues to figure the TMode. The most important, I think
		 * is the cpsr register, when it's available. For auto-pc, the trace recorder ought to have
		 * recorded cpsr at the recorded tick.
		 */

		Register cpsrReg = view.getLanguage().getRegister("cpsr");
		Register tModeReg = view.getLanguage().getRegister("TMode");

		if (cpsrReg == null || tModeReg == null) {
			Msg.error(this, "No cpsr or TMode register in ARM language?: " +
				view.getLanguage().getLanguageID());
			return;
		}

		TraceMemoryRegisterSpace regs =
			view.getTrace().getMemoryManager().getMemoryRegisterSpace(thread, false);
		/**
		 * Some variants (particularly Cortex-M) are missing cpsr This seems to indicate it only
		 * supports THUMB. There is an epsr (xpsr in gdb), but we don't have it in our models, and
		 * its TMode bit must be set, or it will fault.
		 */
		if (regs == null || regs.getState(view.getSnap(), cpsrReg) != TraceMemoryState.KNOWN) {
			command.setInitialContext(new RegisterValue(tModeReg, BigInteger.ONE));
			return;
		}

		RegisterValue cpsrVal = regs.getValue(view.getSnap(), cpsrReg);
		if (isThumbMode(cpsrVal)) {
			command.setInitialContext(new RegisterValue(tModeReg, BigInteger.ONE));
		}
		else {
			command.setInitialContext(new RegisterValue(tModeReg, BigInteger.ZERO));
		}
	}
}
