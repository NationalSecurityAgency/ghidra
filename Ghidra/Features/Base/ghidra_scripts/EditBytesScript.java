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
//Convenience script to quickly clear, edit, and recreate the code or data at the current cursor location.
//@category Memory
//@keybinding
//@menupath 
//@toolbar 
//

import java.util.Map.Entry;
import java.util.TreeMap;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.CodeUnitInsertionException;

public class EditBytesScript extends GhidraScript {

	@Override
	public void run() throws Exception {

		byte[] newBytes = null;
		Address endAddr = null;
		Address activeAddr = null;
		Address codeEnd = null;
		boolean containedInBlock = false;

		while (containedInBlock == false) {
			monitor.checkCanceled();
			newBytes = askBytes("Replace Bytes", "Replace bytes at cursor with:");
			endAddr = currentLocation.getByteAddress().add(newBytes.length - 1);
			activeAddr = currentLocation.getByteAddress();

			containedInBlock = currentProgram.getMemory().getBlock(activeAddr).contains(endAddr);
			if (containedInBlock == true) {
				break;
			}

			popup("Bytes entered cannot be contained in current memory block");
		}

		Address startAddr = currentLocation.getByteAddress();
		activeAddr = currentProgram.getListing().getCodeUnitContaining(activeAddr).getAddress();
		AddressSet addrSet = new AddressSet(activeAddr, endAddr);
		CodeUnitIterator iter = currentProgram.getListing().getCodeUnits(addrSet, true);

		AddressSet codeAddrSet = null;

		TreeMap<Address, DataType> addrToDataTypeMap = new TreeMap<>();
		TreeMap<Address, AddressSet> addrToCodeMap = new TreeMap<>();

		while (iter.hasNext()) {

			activeAddr = iter.next().getAddress();

			Data data = getDataAt(activeAddr);
			if (data != null) {
				DataType dataType = data.getDataType();
				addrToDataTypeMap.put(activeAddr, dataType);
				continue;
			}

			Instruction code = getInstructionContaining(activeAddr);
			if (code != null) {
				codeEnd = activeAddr.add(code.getLength() - 1);
				codeAddrSet = new AddressSet(activeAddr, codeEnd);
				addrToCodeMap.put(activeAddr, codeAddrSet);
				continue;
			}

			if (activeAddr.equals(endAddr)) {
				break;
			}
		}

		clearListing(startAddr, endAddr);

		try {
			setBytes(startAddr, newBytes);
		}
		catch (MemoryAccessException e) {
			popup("Bytes cannot be set on uninitialized memory");
			return;
		}

		for (Entry<Address, DataType> entry : addrToDataTypeMap.entrySet()) {
			try {
				createData(entry.getKey(), entry.getValue());
			}
			catch (CodeUnitInsertionException e) {
				//leaves bytes undefined if there is no 00 byte at the end to
				//make a null terminated string 
				return;
			}
		}

		for (Entry<Address, AddressSet> entry : addrToCodeMap.entrySet()) {
			DisassembleCommand cmd = new DisassembleCommand(entry.getKey(), entry.getValue(), true);
			cmd.applyTo(currentProgram, monitor);
		}
	}
}
