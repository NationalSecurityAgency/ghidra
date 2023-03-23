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
package ghidra.app.plugin.core.debug.disassemble;

import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.CodeUnit;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.listing.TraceInstruction;

public class CurrentPlatformTracePatchInstructionAction
		extends AbstractTracePatchInstructionAction {

	public CurrentPlatformTracePatchInstructionAction(DebuggerDisassemblerPlugin plugin) {
		super(plugin, "Patch Instruction");
	}

	@Override
	protected boolean isApplicableToUnit(CodeUnit cu) {
		if (!super.isApplicableToUnit(cu)) {
			return false;
		}
		return cu instanceof TraceInstruction;
	}

	@Override
	protected TracePlatform getPlatform(CodeUnit cu) {
		// Can safely cast because of isApplicableToUnit
		TraceInstruction ins = (TraceInstruction) cu;
		return ins.getPlatform();
	}

	@Override
	protected RegisterValue getContextValue(CodeUnit cu) {
		TraceInstruction ins = (TraceInstruction) cu;
		return ins.getRegisterValue(ins.getBaseContextRegister());
	}
}
