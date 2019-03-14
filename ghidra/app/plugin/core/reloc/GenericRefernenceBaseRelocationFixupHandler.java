/* ###
 * IP: GHIDRA
 * REVIEWED: YES
 * NOTE: Refernence is a typo in filename
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
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.util.CodeUnitInsertionException;

public class GenericRefernenceBaseRelocationFixupHandler extends RelocationFixupHandler {

	@Override
	public boolean processRelocation(Program program, Relocation relocation, Address oldImageBase,
			Address newImageBase) throws MemoryAccessException, CodeUnitInsertionException {

		int size = program.getCompilerSpec().getDataOrganization().getPointerSize();
		if (size == 4) {
			return handleGenerically32(program, relocation, oldImageBase, newImageBase);
		}
		else if (size == 8) {
			return handleGenerically64(program, relocation, oldImageBase, newImageBase);
		}
		return false;

	}

	@Override
	public boolean handlesProgram(Program program) {
		// always return false so that this is not the chosen handler for a program by the plugin
		return false;
	}

	private boolean hasMatchingReference(Program program, Address address,
			Address candiateRelocationValue) {

		CodeUnit cu = program.getListing().getCodeUnitContaining(address);
		Reference[] referencesFrom = cu.getReferencesFrom();
		for (Reference reference : referencesFrom) {
			if (reference.getToAddress().equals(candiateRelocationValue)) {
				return true;
			}
		}
		return false;
	}

	private boolean handleGenerically64(Program program, Relocation relocation,
			Address oldImageBase, Address newImageBase) throws MemoryAccessException,
			CodeUnitInsertionException {
		long diff = newImageBase.subtract(oldImageBase);

		Address address = relocation.getAddress();
		Memory memory = program.getMemory();
		long value = memory.getLong(address);
		long newValue = value + diff;

		Address candiateRelocationValue = newImageBase.getNewAddress(newValue);
		if (hasMatchingReference(program, address, candiateRelocationValue)) {
			return process64BitRelocation(program, relocation, oldImageBase, newImageBase);
		}

		return false;
	}

	private boolean handleGenerically32(Program program, Relocation relocation,
			Address oldImageBase, Address newImageBase) throws MemoryAccessException,
			CodeUnitInsertionException {

		long diff = newImageBase.subtract(oldImageBase);

		Address address = relocation.getAddress();
		Memory memory = program.getMemory();
		long value = memory.getInt(address) & 0xffffffff;
		int newValue = (int) (value + diff);
		Address candiateRelocationValue = newImageBase.getNewAddress(newValue);
		if (hasMatchingReference(program, address, candiateRelocationValue)) {
			return process32BitRelocation(program, relocation, oldImageBase, newImageBase);
		}
		return false;
	}

}
