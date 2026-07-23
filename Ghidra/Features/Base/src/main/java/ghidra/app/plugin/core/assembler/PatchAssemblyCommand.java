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
package ghidra.app.plugin.core.assembler;

import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.framework.cmd.Command;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Program;

public class PatchAssemblyCommand extends AbstractPatchAssemblyCommand<Program> {

	public PatchAssemblyCommand(Assembler asm, List<String> lines, Address entry,
			RegisterValue initialContext) {
		super(asm, lines, entry, initialContext);
	}

	public PatchAssemblyCommand(Assembler asm, String string, Address entry,
			RegisterValue initialContext) {
		super(asm, string, entry, initialContext);
	}

	@Override
	protected Command<Program> newDisassembleCommand(AddressSetView set, Program program) {
		DisassembleCommand dis = new DisassembleCommand(entry, set, false);
		dis.setInitialContext(initialContext);
		return dis;
	}
}
