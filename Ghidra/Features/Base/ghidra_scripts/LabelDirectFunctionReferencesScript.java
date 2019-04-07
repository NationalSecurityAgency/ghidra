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
//This script searches for direct memory references to existing functions.
//When a reference is found a new "ptr_functionName_refAddress" is applied
// only works on 32 bit programs
//Check the console for a list of references that have been added.
//@category Analysis

import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramUtilities;
import ghidra.util.task.TaskMonitor;

public class LabelDirectFunctionReferencesScript extends GhidraScript {

	Listing listing;
	Memory memory;
	SymbolTable symbolTable;

	@Override
	public void run() throws Exception {
		listing = currentProgram.getListing();
		memory = currentProgram.getMemory();
		symbolTable = currentProgram.getSymbolTable();

		int size = currentProgram.getMinAddress().getSize();
		if (size != 32) {
			popup("This script only works on 32-bit programs");
			return;
		}

		monitor.setMessage("Labeling direct references to functions");

		List<Function> funcSet = new ArrayList<>();
		List<Address> resultSet = new ArrayList<>();
		List<Address> refs = new ArrayList<>();

		FunctionIterator funcIter = listing.getFunctions(true);
		while (funcIter.hasNext() && !monitor.isCancelled()) {
			funcSet.add(funcIter.next());
		}
		if (funcSet.size() == 0) {
			popup("No functions found.  Try analyzing code first.");
			return;
		}

		for (int i = 0; i < funcSet.size(); i++) {
			Function func = funcSet.get(i);
			refs = findRefs(func.getEntryPoint(), monitor);
			for (int j = 0; j < refs.size(); j++) {
				Data data = getDataAt(refs.get(j));
				//	if((data != null) && data.isDefined() && ((data.getBaseDataType().getName() == "dword") || (data.getBaseDataType().getName() == "pointer32"))){
				if ((data != null) && data.isDefined() &&
					(("dword".equals(data.getBaseDataType().getName())) || (data.isPointer()))) {
					resultSet.add(refs.get(j));
					String newLabel = "ptr_" + func.getName(false) + "_" + refs.get(j).toString();
					println(newLabel);
					Symbol sym =
						symbolTable.createLabel(refs.get(j), newLabel, SourceType.ANALYSIS);
					if (!sym.isPrimary()) {
						sym.setPrimary();
					}
				}
			}

		}
	}

	List<Address> findRefs(Address fromAddr, TaskMonitor taskMonitor) throws MemoryAccessException {
		List<Address> foundRefs = new ArrayList<>();
		String hexString = toHexString((int) fromAddr.getUnsignedOffset(), true, false);
		byte[] bytes = getBytesAsHex(hexString, 4);
		//println(fromAddr.toString() + " : " + hexString + " " + bytes[0] + " " + bytes[1] + " " + bytes[2] + " " + bytes[3]);
		if (!currentProgram.getMemory().isBigEndian()) {
			bytes = reverseByteArray(bytes, 4, 4);
		}
		//println(fromAddr.toString() + " : " + hexString + " " + bytes[0] + " " + bytes[1] + " " + bytes[2] + " " + bytes[3]);
		Data data = getFirstData();
		while ((data != null) && !ProgramUtilities.getByteCodeString(data).contains("??") &&
			(!taskMonitor.isCancelled())) {
			if (Arrays.equals(data.getBytes(), bytes)) {
				foundRefs.add(data.getMinAddress());
			}
			data = getDataAfter(data);

		}
		return foundRefs;
	}

	public byte[] reverseByteArray(byte[] bytes, int arrayLen, int reverseLen) {
		if (reverseLen == 0) {
			return bytes;
		}
		byte[] revbytes;
		if (arrayLen % reverseLen == 0) {
			revbytes = new byte[arrayLen];
			for (int i = 0; i < arrayLen; i += reverseLen) {
				for (int j = 0; j < reverseLen; j++) {
					revbytes[i + j] = bytes[i + (reverseLen - j - 1)];
				}
			}
		}
		else {
			revbytes = null;
		}
		return (revbytes);
	}

	public byte[] getBytesAsHex(String str, int numBytes) {

		Integer iByte;
		byte[] bytes = new byte[numBytes];
		String sub;

		for (int i = 0; i < (numBytes) * 2; i += 2) {
			sub = str.substring(i, i + 2); // get byte substring
			iByte = Integer.valueOf(sub, 16); // turn substring into hex
												// Integer
			bytes[i / 2] = iByte.byteValue(); // turn hex Integer into byte
		}

		return bytes;
	}
}
