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

import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class DemangledAddressTable extends DemangledObject {

	private boolean calculateLength;
	private int length;

	/**
	 * Constructor
	 * 
	 * @param mangled the source mangled string 
	 * @param originalDemangled the original demangled string
	 * @param name the name of the address table
	 * @param calculateLength true if the length of this address table should be calculdated at 
	 *        analysis time
	 */
	public DemangledAddressTable(String mangled, String originalDemangled, String name,
			boolean calculateLength) {
		super(mangled, originalDemangled);
		setName(name);
		this.calculateLength = calculateLength;
	}

	/**
	 * Returns the length of the address table.
	 * -1 indicates the length is unknown.
	 * @return the length of the address table
	 */
	public int getLength() {
		return length;
	}

	@Override
	public String getSignature(boolean format) {
		StringBuffer buffer = new StringBuffer();

		if (specialPrefix != null) {
			buffer.append(specialPrefix);
			buffer.append(' ');
		}
		String namespaceStr = namespace.getNamespaceString();
		buffer.append(namespaceStr);
		if (!namespaceStr.endsWith(NAMESPACE_SEPARATOR)) {
			buffer.append(NAMESPACE_SEPARATOR);
		}
		buffer.append(getDemangledName());

		return buffer.toString();
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

		Symbol s = applyDemangledName(address, true, false, program);
		if (s == null) {
			return false;
		}

		Listing listing = program.getListing();
		if (MemoryBlock.isExternalBlockAddress(address, program)) {
			listing.setComment(address, CodeUnit.EOL_COMMENT,
				"WARNING: Unable to apply demangled Address Table");
			return true; // don't complain
		}

		if (calculateLength) {
			// determine length of address table
			Data d = listing.getDefinedDataAt(address);
			if (d != null && Undefined.isUndefinedArray(d.getDataType())) {
				// use length of Undefined array at start of table to indicate length
				length = d.getLength();
			}
			else {
				length = guessTableLength(program, address);
				if (length <= 0) {
					return false;
				}
			}
			calculateLength = false;
		}

		if (isUndefinedInRange(program, address, address.add(length - 1))) {
			long count = length / program.getDefaultPointerSize();
			createPointers(program, address, (int) count);
		}

		return true;
	}

	/**
	 * Perform a best guess at the length of an address table assuming that 
	 * another label (or end of block) can be used to identify the end.
	 * @param program the program
	 * @param address start of address table
	 * @return maximum length of table or -1 if address does not reside 
	 * within an initialized memory block
	 */
	private static int guessTableLength(Program program, Address address) {
		MemoryBlock block = program.getMemory().getBlock(address);
		if (block == null || !block.isInitialized()) {
			return -1;
		}
		Address endAddr = block.getEnd();
		Symbol nextsym = findNextImportedSymbol(program, address);
		if (nextsym != null && nextsym.getAddress().compareTo(endAddr) < 0) {
			endAddr = nextsym.getAddress();
		}
		return (int) endAddr.subtract(address);
	}

	private static Symbol findNextImportedSymbol(Program program, Address address) {
		int count = 0;
		SymbolIterator symiter = program.getSymbolTable().getSymbolIterator(address.add(1), true);
		while (symiter.hasNext()) {
			Symbol nextsym = symiter.next();
			if (nextsym.getSource() == SourceType.IMPORTED) {
				return nextsym;
			}
			if (++count > 50) {
				break;//don't look more than 50 symbols ahead...
			}
		}
		return null;
	}

	/**
	 * Creates pointers from start address.
	 * If a pointer already exists, then skip it and continue.
	 */
	private void createPointers(Program program, Address start, int count) {

		DataType pointerDt = new PointerDataType(program.getDataTypeManager());

		Listing listing = program.getListing();
		Memory mem = program.getMemory();
		DumbMemBufferImpl buf = new DumbMemBufferImpl(mem, start);

		for (int i = 0; i < count; ++i) {

			Address addr = start.add(pointerDt.getLength() * i);
			buf.setPosition(addr);

			Address refAddr = (Address) pointerDt.getValue(buf, null, -1);
			if (refAddr == null) {
				// terminate table early if unable to produce address - bytes correspond to illegal offset
				return;
			}
			if (refAddr.getOffset() == 0) {
				// skip over 0 offsets which may be a result of an unsupported relocation
				// or runtime initialized bytes
				continue;
			}

			Data d = listing.getDefinedDataAt(addr);
			if (d != null && d.isPointer()) {
				// skip locations where pointer already exists
				continue;
			}

			if (!mem.contains(refAddr)) {
				// terminate table early if pointer reference address does not exist
				// within memory (demangled address tables should only refer to entities 
				// contained within program memory).
				return;
			}

			CreateDataCmd cmd = new CreateDataCmd(addr, false, false, pointerDt);
			if (!cmd.applyTo(program)) {
				Msg.debug(this, "Unable to demangled address table pointer at " + addr + ": " +
					cmd.getStatusMsg());
				return;
			}
		}
	}

	private boolean isUndefinedInRange(Program program, Address start, Address end) {

		InstructionIterator instructions = program.getListing().getInstructions(start, true);
		if (instructions.hasNext()) {
			Instruction instr = instructions.next();
			if (instr.getMinAddress().compareTo(end) <= 0) {
				return false;
			}
		}

		DataIterator definedData = program.getListing().getDefinedData(start, true);
		while (definedData.hasNext()) {
			Data data = definedData.next();
			if (data.getMinAddress().compareTo(end) > 0) {
				break;
			}
			if (!Undefined.isUndefined(data.getDataType()) &&
				!(data.getDataType() instanceof Pointer)) {//ok if pointer is already applied
				return false;
			}
		}

		return true;
	}
}
