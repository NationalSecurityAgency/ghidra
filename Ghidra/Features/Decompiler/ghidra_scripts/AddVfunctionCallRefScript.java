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
// This script requires the cursor to be on a vftable->function token in the decompiler and will 
// create a CALL reference to the associated function in the listing if it is possible to identify a
// single corresponding applied vftable structure and identify the associated function in the 
// listing. 
//
//@category C++

import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;

public class AddVfunctionCallRefScript extends GhidraScript {
	private DecompInterface decomplib;
	DecompileResults lastResults = null;

	@Override
	public void run() throws Exception {

		try {
			// get the decompiler context
			// setup the decompiler
			decomplib = setUpDecompiler(currentProgram);
			if (decomplib == null) {
				println("Could not setup the decompiler.");
				return;
			}

			// get the function associated with the current cursor location in the decompiler
			// if the cursor is not on a vftable->function construct then it will return null
			// if a single function cannot be tied to this construct then return null
			Function function = getFunctionAtLocation();

			// previous function spits out appropriate error message if it returns null
			if (function == null) {
				return;
			}

			println("Associated function found: " + function.getEntryPoint());

			Address associatedAddress = getAssociatedAddress();
			if (associatedAddress == null) {
				println("Cannot find single associated listing address to put reference on.");
				return;
			}

			// add reference to the function on the CALL operand
			addOperandReference(associatedAddress, function);
			println("Reference added to " + associatedAddress.toString());

			// uncomment this line to add a comment link 
			//setPreComment(associatedAddress, "{@symbol " + function.getEntryPoint() + "}");

		}
		finally {
			if (decomplib != null) {
				decomplib.dispose();
			}
		}
	}

	private void addOperandReference(Address address, Function function) {

		Instruction instruction = currentProgram.getListing().getInstructionAt(address);
		instruction.addOperandReference(0, function.getEntryPoint(), RefType.UNCONDITIONAL_CALL,
			SourceType.ANALYSIS);
	}

	private Function getFunctionAtLocation() throws CancelledException {

		if (currentLocation instanceof DecompilerLocation dloc) {

			// get the Varnode under the cursor
			ClangToken tokenAtCursor = dloc.getToken();
			Structure structure = getStructure(tokenAtCursor);
			if (structure == null) {
				println(
					"Cursor is not in a valid structure token. Put cursor on a decompiler structure->function name.");
				return null;
			}
			println("Structure containing cursor token: " + structure.getDisplayName());

			// check that the struct is all function pointers
			if (!isVftableStructure(structure)) {
				println("This script only works for structures that contain all function pointers");
				return null;
			}

			List<Address> appliedData = getAppliedData(structure);
			if (appliedData.size() == 0) {
				println("No applied structure " + structure.getDisplayName() +
					" so cannot find associated function.");
				return null;
			}
			if (appliedData.size() > 1) {
				println("Multiple applied structures " + structure.getDisplayName() +
					" so cannot find associated function");
				return null;
			}

			Address singleAppliedStructAddress = appliedData.get(0);

			println("Single " + structure.getDisplayName() + " found at " +
				singleAppliedStructAddress.toString());

			String functionName = tokenAtCursor.toString();
			Integer offsetOfFunction = getOrdinalOfFunction(structure, functionName);
			if (offsetOfFunction == null) {
				println("No function named " + functionName + " in structure " +
					structure.getPathName() + " so cannot find associated function");
				return null;
			}

			int defaultPointerSize = currentProgram.getDefaultPointerSize();

			Address referencedAddress = getReferencedAddress(currentProgram,
				singleAppliedStructAddress.add(defaultPointerSize * offsetOfFunction), true);
			if (referencedAddress == null) {
				println("No referenced address at offset " + offsetOfFunction);
				return null;
			}

			Function function = currentProgram.getListing().getFunctionAt(referencedAddress);
			if (function == null) {
				println("No function at: " + referencedAddress.toString());
				return null;
			}

			if (function.isThunk()) {
				function = function.getThunkedFunction(true);
			}

			return function;

		}

		return null;

	}

	private Address getAssociatedAddress() {

		if (currentLocation instanceof DecompilerLocation dloc) {
			// get the Varnode under the cursor
			ClangToken token = dloc.getToken();

			// return the closest single associated address in the listing
			return DecompilerUtils.getClosestAddress(currentProgram, token);
		}
		return null;
	}

	private Structure getStructure(ClangToken token) {

		DataType dataType = DecompilerUtils.getDataType(token);
		if (!(dataType instanceof Structure)) {
			return null;
		}

		return (Structure) dataType;

	}

	private List<Address> getAppliedData(DataType dataType) throws CancelledException {

		List<Address> appliedData = new ArrayList<>();
		Listing listing = currentProgram.getListing();
		DataIterator definedData = listing.getDefinedData(true);
		while (definedData.hasNext()) {
			monitor.checkCancelled();

			Data nextData = definedData.next();
			if (nextData.getDataType().equals(dataType)) {
				appliedData.add(nextData.getAddress());
			}
		}
		return appliedData;

	}

	private Integer getOrdinalOfFunction(Structure struct, String name) {

		for (DataTypeComponent component : struct.getComponents()) {
			DataType dataType = component.getDataType();
			if (dataType instanceof Pointer ptr) {
				dataType = ptr.getDataType();
			}

			if (dataType.getName().equals(name)) {
				return component.getOrdinal();
			}
		}
		return null;
	}

	// validate that structure contains only functionDef*'s
	private boolean isVftableStructure(Structure struct) {

		for (DataTypeComponent component : struct.getComponents()) {
			DataType dataType = component.getDataType();
			if (!(dataType instanceof Pointer ptr)) {
				return false;
			}

			dataType = ptr.getDataType();
			if (!(dataType instanceof FunctionDefinition)) {
				return false;
			}
		}
		return true;
	}

	private DecompInterface setUpDecompiler(Program program) {

		DecompInterface decompInterface = new DecompInterface();

		// call it to get results
		if (!decompInterface.openProgram(currentProgram)) {
			println("Decompile Error: " + decompInterface.getLastMessage());
			return null;
		}

		DecompileOptions options = DecompilerUtils.getDecompileOptions(state.getTool(), program);

		decompInterface.setOptions(options);

		decompInterface.toggleCCode(true);
		decompInterface.toggleSyntaxTree(true);
		decompInterface.setSimplificationStyle("decompile");

		return decompInterface;
	}

	/**
	 * Method to return the referenced address at the given address in the given program
	 * Note: this will work whether there is a created reference or not
	 * @param program the given program
	 * @param addr the address to look for a referenced address at
	 * @param getIboIf64bit if true, get the address corresponding to the image base offset instead 
	 * of the full reference address
	 * @return the first referenced address from the given address
	 */
	public static Address getReferencedAddress(Program program, Address addr,
			boolean getIboIf64bit) {

		int addressSize = addr.getSize();
		if (addressSize == 64 && getIboIf64bit) {
			IBO32DataType ibo32 = new IBO32DataType(program.getDataTypeManager());
			int length = ibo32.getLength();
			DumbMemBufferImpl compMemBuffer = new DumbMemBufferImpl(program.getMemory(), addr);
			Object value = ibo32.getValue(compMemBuffer, ibo32.getDefaultSettings(), length);
			if (value instanceof Address iboAddress) {
				return iboAddress;
			}
			return null;
		}

		long offset;
		try {
			if (addressSize == 32) {
				Integer offset32 = program.getMemory().getInt(addr);
				offset = Integer.toUnsignedLong(offset32);
			}
			else if (addressSize == 64) {
				offset = program.getMemory().getLong(addr);
			}
			else {
				return null;
			}
			Address newAddr = addr.getNewAddress(offset);
			if (program.getMemory().contains(newAddr)) {
				return newAddr;
			}
			return null;
		}
		catch (MemoryAccessException e) {
			return null;
		}

	}

}
