/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.reloc;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.classfinder.ExtensionPoint;

public abstract class RelocationFixupHandler implements ExtensionPoint {

	public abstract boolean processRelocation(Program program, Relocation relocation,
			Address oldImageBase, Address newImageBase) throws MemoryAccessException,
			CodeUnitInsertionException;

	public abstract boolean handlesProgram(Program program);

	protected boolean process32BitRelocation(Program program, Relocation relocation,
			Address oldImageBase, Address newImageBase) throws MemoryAccessException,
			CodeUnitInsertionException {
		long diff = newImageBase.subtract(oldImageBase);

		Address address = relocation.getAddress();
		Memory memory = program.getMemory();
		int value = memory.getInt(address);
		int newValue = (int) (value + diff);

		InstructionStasher instructionStasher = new InstructionStasher(program, address);

		memory.setInt(address, newValue);

		instructionStasher.restore();

		return true;
	}

	public boolean process64BitRelocation(Program program, Relocation relocation,
			Address oldImageBase, Address newImageBase) throws MemoryAccessException,
			CodeUnitInsertionException {

		long diff = newImageBase.subtract(oldImageBase);

		Address address = relocation.getAddress();
		Memory memory = program.getMemory();
		long value = memory.getLong(address);
		long newValue = value + diff;

		InstructionStasher instructionStasher = new InstructionStasher(program, address);

		memory.setLong(address, newValue);

		instructionStasher.restore();

		return true;
	}
}
