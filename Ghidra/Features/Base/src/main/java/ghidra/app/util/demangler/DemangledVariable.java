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
package ghidra.app.util.demangler;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.util.PseudoDisassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.task.TaskMonitor;

/**
 * An interface to represent a demangled global variable.
 */
public class DemangledVariable extends DemangledObject {
	private DemangledDataType datatype;

	public DemangledVariable(String mangled, String originalDemangled, String name) {
		super(mangled, originalDemangled);
		setName(name);
	}

	public void setDatatype(DemangledDataType datatype) {
		this.datatype = datatype;
	}

	/**
	 * Returns the data type of this variable.
	 * @return the data type of this variable
	 */
	public DemangledDataType getDataType() {
		return datatype;
	}

	private DataType getProgramDataType(Program program) {
		if (datatype != null) {
			return datatype.getDataType(program.getDataTypeManager());
		}
		return null;
	}

	@Override
	public String getSignature(boolean format) {
		StringBuilder buffer = new StringBuilder();
		buffer.append(specialPrefix == null ? EMPTY_STRING : specialPrefix + SPACE);
		buffer.append(
			visibility == null || "global".equals(visibility) ? EMPTY_STRING : visibility + SPACE);

		buffer.append(isStatic ? "static" + SPACE : EMPTY_STRING);

		buffer.append(isVirtual ? "virtual" + SPACE : EMPTY_STRING);

		String n = getDemangledName();
		boolean hasName = !StringUtils.isBlank(n);

		StringBuilder datatypeBuffer = new StringBuilder();
		String spacer = EMPTY_STRING;
		if (!(datatype instanceof DemangledFunctionPointer) &&
			!(datatype instanceof DemangledFunctionReference) &&
			!(datatype instanceof DemangledFunctionIndirect)) {
			if (datatype != null) {
				datatypeBuffer.append(datatype.getSignature());
				spacer = SPACE;
			}
		}

		// e.g., 'const' - this appears after the data type in MS land
		if (storageClass != null) {
			datatypeBuffer.append(spacer).append(storageClass);
			spacer = SPACE;
		}

		if (isConst()) {
			datatypeBuffer.append(spacer).append("const");
			spacer = SPACE;
		}

		if (isVolatile()) {
			datatypeBuffer.append(spacer).append("volatile");
			spacer = SPACE;
		}

		if (basedName != null) {
			datatypeBuffer.append(spacer).append(basedName);
			spacer = SPACE;
		}

		if ((memberScope != null) && (memberScope.length() != 0)) {
			datatypeBuffer.append(spacer).append(memberScope + "::");
			spacer = SPACE;
		}

		if (isUnaligned()) {
			datatypeBuffer.append(spacer).append("__unaligned");
			spacer = SPACE;
		}

		if (isPointer64()) {
			datatypeBuffer.append(spacer).append("__ptr64");
			spacer = SPACE;
		}

		if (isRestrict()) {
			datatypeBuffer.append(spacer).append("__restrict");
			spacer = SPACE;
		}

		if (namespace != null) {

			datatypeBuffer.append(spacer);
			spacer = EMPTY_STRING;

			datatypeBuffer.append(namespace.getNamespaceString());

			if (hasName) {
				datatypeBuffer.append(NAMESPACE_SEPARATOR);
			}
		}

		if (hasName) {
			datatypeBuffer.append(spacer);
			spacer = EMPTY_STRING;
			datatypeBuffer.append(getName());
		}

		if (datatype instanceof DemangledFunctionPointer) {
			DemangledFunctionPointer funcPtr = (DemangledFunctionPointer) datatype;
			return buffer.append(funcPtr.toSignature(datatypeBuffer.toString())).toString();
		}
		else if (datatype instanceof DemangledFunctionReference) {
			DemangledFunctionReference funcRef = (DemangledFunctionReference) datatype;
			return buffer.append(funcRef.toSignature(datatypeBuffer.toString())).toString();
		}
		else if (datatype instanceof DemangledFunctionIndirect) {
			DemangledFunctionIndirect funcDef = (DemangledFunctionIndirect) datatype;
			return buffer.append(funcDef.toSignature(datatypeBuffer.toString())).toString();
		}

		buffer.append(datatypeBuffer);

		return buffer.toString();
	}

	@Override
	protected boolean isAlreadyDemangled(Program program, Address address) {
		Data data = program.getListing().getDefinedDataAt(address);
		if (data == null || Undefined.isUndefined(data.getDataType())) {
			return false;
		}
		return super.isAlreadyDemangled(program, address);
	}

	@Override
	public boolean applyTo(Program program, Address address, DemanglerOptions options,
			TaskMonitor monitor) throws Exception {

		if (isAlreadyDemangled(program, address)) {
			return true;
		}

		if (!super.applyTo(program, address, options, monitor)) {
			return false;
		}

		Symbol demangledSymbol = applyDemangledName(address, true, true, program);
		DataType demangledDT = getProgramDataType(program);

		if (address.isExternalAddress()) {
			if (demangledSymbol == null) {
				throw new AssertException("Undefined external address: " + address);
			}
			if (demangledDT != null) {
				ExternalLocation extLoc = (ExternalLocation) demangledSymbol.getObject();
				extLoc.setDataType(demangledDT);
			}
			return true;
		}

		Listing listing = program.getListing();

		Data d = listing.getDefinedDataAt(address);
		if (d != null) {
			if (demangledDT == null || !Undefined.isUndefined(d.getDataType())) {
				return true; // preserve existing data quietly
			}
		}

		if (demangledDT != null) {
			CreateDataCmd cmd = new CreateDataCmd(address, demangledDT, false,
				ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			if (!cmd.applyTo(program)) {
				Msg.error(this, "Failed to create data at " + address + ": " + cmd.getStatusMsg());
				return false;
			}
			return true;
		}

		// if the block is marked Executable, don't worry about creating data here
		// unless we really know what type of data it is
		MemoryBlock block = program.getMemory().getBlock(address);
		if (block == null || block.isExecute()) {
			return true;
		}

		// get the symbol after this one.  If smaller than pointer, can't be a pointer
		Address nextSymbolLoc = getNextSymbolLocation(program, address);

		// could be a pointer
		long maximumDataTypeSize = nextSymbolLoc.subtract(address);
		if (createPointer(program, address, maximumDataTypeSize)) {
			return true;
		}

		// Create an undefined data type here to stop any code from being created.
		// Might have to change the data reference creation to ignore undefined data types
		//   when trying to figure out what the data is.
		if (d != null) {
			// something is already there
			return true;
		}

		int size = (maximumDataTypeSize <= 8) ? (int) maximumDataTypeSize : 1;
		demangledDT = Undefined.getUndefinedDataType(size);

		try {
			listing.createData(address, demangledDT);
		}
		catch (CodeUnitInsertionException e) {
			Msg.trace(this, "Unable to create demangled data '" + demangledDT + "' @ " + address);
		}

		return true; // return true, as we did not fail to demangle
	}

	@Override
	public String getName() {
		String myName = super.getName();
		if (!myName.isEmpty()) {
			return myName;
		}

		// some variables don't have names, but use the name of their datatype
		if (datatype != null) {
			return datatype.getName();
		}

		String signature = getSignature(true);
		String fixed = SymbolUtilities.replaceInvalidChars(signature, true);
		return fixed;
	}

	private boolean createPointer(Program program, Address address, long maximumDataTypeSize) {

		if (maximumDataTypeSize < address.getPointerSize()) {
			return false;
		}

		PseudoDisassembler pdis = new PseudoDisassembler(program);
		Address indirectAddress = pdis.getIndirectAddr(address);
		if (indirectAddress == null) {
			return false;
		}

		if (!program.getMemory().contains(indirectAddress)) {
			return false;
		}

		SymbolTable symbolTable = program.getSymbolTable();
		Symbol primarySymbol = symbolTable.getPrimarySymbol(indirectAddress);
		if (primarySymbol != null && primarySymbol.getSource() != SourceType.DEFAULT) {
			return createPointer(program, address);
		}

		Listing listing = program.getListing();
		Data data = listing.getDataAt(indirectAddress);
		if (data != null && data.isDefined()) {
			return createPointer(program, address);
		}

		return false;
	}

	private boolean createPointer(Program program, Address address) {
		PointerDataType pointer = new PointerDataType(program.getDataTypeManager());
		CreateDataCmd cmd = new CreateDataCmd(address, pointer, false,
			ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
		if (!cmd.applyTo(program)) {
			Msg.error(this, "Failed to create pointer at " + address + ": " + cmd.getStatusMsg());
			return false;
		}
		return true;
	}

	/**
	 * get the next symbol defined or auto after address
	 * 
	 * @param program - program to check
	 * @param address - address to get symbol after
	 * @return address of the location of the next symbol or the last address in program
	 */
	private Address getNextSymbolLocation(Program program, Address address) {
		SymbolIterator symIter = program.getSymbolTable().getSymbolIterator(address.add(1), true);
		if (symIter.hasNext()) {
			Symbol nextSym = symIter.next();
			if (nextSym != null) {
				return nextSym.getAddress();
			}
		}
		return program.getMaxAddress();
	}
}
