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
//Example script to show how to export the current program in its original binary format by 
//looking at the original bytes compared to the current bytes and exporting the original if they 
//are the same and the current bytes if they are different. If the changed bytes are relocations, 
//the original bytes are used. The script only handles simple use cases.
//@category Examples

import java.io.*;
import java.util.Iterator;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.util.exception.CancelledException;

public class ExportProgramScript extends GhidraScript {

	@Override
	public void run() throws Exception {

		if (currentProgram == null) {
			println("Must have an open program");
			return;
		}

		File outBinaryFile = askFile("Select Binary Output File", "Binary File");

		if (outBinaryFile.exists()) {
			if (!askYesNo("Binary File Already Exists",
				"The binary file already exists.\nDo you want to overwrite it?")) {
				return;
			}
		}

		// make address set of relocation byte addresses
		AddressSet relocationAddrs = new AddressSet();

		RelocationTable relocTable = currentProgram.getRelocationTable();
		Iterator<Relocation> iter = relocTable.getRelocations();
		while (iter.hasNext()) {
			monitor.checkCanceled();

			Relocation reloc = iter.next();
			Address relocStart = reloc.getAddress();

			int rlocLen = reloc.getBytes().length;
			relocationAddrs.add(relocStart, relocStart.add(rlocLen));
		}

		// create an output stream
		OutputStream out = new FileOutputStream(outBinaryFile);

		// get all program file bytes
		Memory memory = currentProgram.getMemory();
		List<FileBytes> allFileBytes = memory.getAllFileBytes();
		if (allFileBytes.isEmpty()) {
			println(
				"Cannot access original file bytes. Either the program was imported before Ghidra " +
					"started saving original file bytes or the program was not imported directly from the " +
					"original binary.");
			out.close();
			return;
		}

		//TODO: update to handle multiple case once FileBytes adds new method to support it
		if (allFileBytes.size() > 1) {
			println(
				"*** This program was created using multiple imported programs. This script will currently only work if the program was created with a single imported file.");
			out.close();
			return;
		}

		//Get the original import file bytes
		FileBytes fileBytes = allFileBytes.get(0);

		long size = fileBytes.getSize();
		println(
			"Exporting current program to a new binary file including any changes to the original " +
				"except for relocation changes...");

		// compare each original imported byte with the current program byte at the equivalent location
		// if the current byte is different and is not a relocation, export that byte instead of
		// the original
		for (long i = 0; i < size; i++) {

			monitor.checkCanceled();

			byte originalByte = fileBytes.getOriginalByte(i);
			byte currentByte = fileBytes.getModifiedByte(i);

			int original = originalByte & 0xff;
			int current = currentByte & 0xff;

			if (originalByte != currentByte) {

				// TODO: once new method is created to use the fileBytes and offset to retrieve the
				// address, update this to use the correct method and lift the above restriction 
				// on only handling one imported file.
				List<Address> addresses = memory.locateAddressesForFileOffset(i);


				// NOTE: It is rare that there would be more than one address in the program corresponding
				// to a given offset but check anyway and if any of them are a relocation then 
				// output the original byte
				if (!addressSetContainsAnyInList(relocationAddrs, addresses)) {

					println(addresses +
						": Writing out changed byte since it is not a relocation. File offset = " +
						i + ", originalByte = " + Integer.toHexString(original) +
						", changed to = " + Integer.toHexString(current));
					println("****** ");
					out.write(current);

				}
				else {
					// Not writing out change since it is a relocation
					out.write(original);
				}

			}
			// same in current and original
			else {
				out.write(original);
			}
		}

		out.close();
		println("Done!");
	}

	private boolean addressSetContainsAnyInList(AddressSet set, List<Address> list)
			throws CancelledException {

		if (list.isEmpty()) {
			return false;
		}
		if (set.isEmpty()) {
			return false;
		}

		for (Address address : list) {
			monitor.checkCanceled();
			if (set.contains(address)) {
				return true;
			}
		}
		return false;
	}
}
