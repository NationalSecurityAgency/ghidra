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
package ghidra.util.state.analysis;

import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.state.VarnodeOperation;

public class TableEntry extends Switch {

	private final Program program;
	private final TableEntryAddress tableEntryAddress;
	private final int size;
	private boolean signExtend;

	private TableEntry(Program program, TableEntryAddress tableEntryAddress, int entrySize,
			boolean signExtend) {
		this.program = program;
		this.tableEntryAddress = tableEntryAddress;
		this.size = entrySize;
		this.signExtend = signExtend;
	}

	/**
	 * Returns table entry size in bytes
	 */
	int getTableEntrySize() {
		return size;
	}

	@Override
	Varnode getIndexValue() {
		return tableEntryAddress.getIndexValue();
	}

	/**
	 * Returns table entry value for specified caseIndexValue.
	 * @param caseIndexValue index value for specific case
	 * @param scaleFactor scale factor, generally this should be 1
	 * @param createTableData if true an attempt will be made to create associated Data in table
	 * @return value loaded from the table entry in memory which corresponds to the specified caseIndexValue.
	 * @throws MemoryAccessException 
	 */
	long getTableEntryValue(int caseIndexValue, int scaleFactor, boolean createTableData)
			throws MemoryAccessException {
		Address entryAddr = tableEntryAddress.getCaseAddress(caseIndexValue);
		if (createTableData) {
			createData(program.getListing(), entryAddr);
		}
		return getLongValue(program, entryAddr, scaleFactor, size, signExtend);
	}

	/**
	 * Returns table entry value as pointer for specified caseIndexValue.
	 * @param caseIndexValue index value for specific case
	 * @param scaleFactor scale factor, generally this should be 1
	 * @param createTableData if true an attempt will be made to create associated Data in table
	 * @return pointer loaded from the table entry in memory which corresponds to the specified caseIndexValue.
	 * @throws MemoryAccessException
	 * @throws AddressOutOfBoundsException
	 */
	Address getTableEntryAsAddress(int caseIndexValue, int scaleFactor, boolean createTableData)
			throws MemoryAccessException, AddressOutOfBoundsException {
		Address entryAddr = tableEntryAddress.getCaseAddress(caseIndexValue);
		if (createTableData) {
			createPointer(entryAddr, scaleFactor);
		}
		long offset = getLongValue(program, entryAddr, scaleFactor, size, false);
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	/**
	 * Returns table entry value as pointer for specified caseIndexValue.
	 * @param caseIndexValue index value for specific case
	 * @return pointer loaded from the table entry in memory which corresponds to the specified caseIndexValue.
	 * @throws MemoryAccessException
	 * @throws AddressOutOfBoundsException
	 */
	@Override
	Address getCaseAddress(int caseIndexValue) throws MemoryAccessException,
			AddressOutOfBoundsException {
		return getTableEntryAsAddress(caseIndexValue, 1, false);
	}

	private void createPointer(Address entryAddr, int scaleFactor) {
		DataType ptrDt;
		if (scaleFactor != 1) {
			// compiler spec data organization supports at most one shifted address scaleFactor (see ShiftedAddressDataType)
			DataOrganization dataOrg = program.getDataTypeManager().getDataOrganization();
			int shiftFactor = 1 << dataOrg.getPointerShift();
			if (size == dataOrg.getPointerSize() && scaleFactor == shiftFactor) {
				ptrDt = ShiftedAddressDataType.dataType;
			}
			else {
				// Unknown pointer data type
				return;
			}
		}
		else {
			ptrDt = PointerDataType.getPointer(DataType.DEFAULT, size);
		}
		CreateDataCmd cmd = new CreateDataCmd(entryAddr, ptrDt);
		cmd.applyTo(program);
	}

	private void createData(Listing listing, Address entryAddr) {
		DataType primitiveDt;
		switch (size) {
			case 1:
				primitiveDt = new ByteDataType();
				break;
			case 2:
				primitiveDt = new ByteDataType();
				break;
			case 4:
				primitiveDt = new ByteDataType();
				break;
			case 8:
				primitiveDt = new ByteDataType();
				break;
			default:
				return;
		}
		CreateDataCmd cmd = new CreateDataCmd(entryAddr, primitiveDt);
		cmd.applyTo(program);
	}

	static long getLongValue(Program program, Address entryAddr, int scaleFactor, int size,
			boolean signExtend) throws MemoryAccessException {
		byte[] bytes = new byte[size];
		Memory mem = program.getMemory();
		if (mem.getBytes(entryAddr, bytes) != size) {
			throw new MemoryAccessException("Failed to read table entry at: " + entryAddr);
		}
		long val = 0;
		if (program.getLanguage().isBigEndian()) {
			if (signExtend && (bytes[0] < 0)) {
				val = -1;
			}
			for (int i = 0; i < size; i++) {
				val = (val << 8) + ((long) bytes[i] & 0x0ff);
			}
		}
		else {
			if (signExtend && (bytes[size - 1] < 0)) {
				val = -1;
			}
			for (int i = size - 1; i >= 0; i--) {
				val = (val << 8) + ((long) bytes[i] & 0x0ff);
			}
		}
		return val * scaleFactor;
	}

	/**
	 * Qualify TableEntry as LOAD(table-entry-address)
	 * and return TableEntry if qualified or null if not.
	 * @param program
	 * @param v potential input value which corresponds to a switch table entry
	 * @return TableEntry object or null if v failed qualification
	 */
	static TableEntry getTableEntry(Program program, Varnode v) {
		if (!(v instanceof VarnodeOperation)) {
			return null;
		}
		VarnodeOperation op = (VarnodeOperation) v;
		int opcode = op.getPCodeOp().getOpcode();
		boolean signExtend = false;
		if (opcode == PcodeOp.INT_SEXT || opcode == PcodeOp.INT_ZEXT) {
			v = op.getInputValues()[0];
			signExtend = (opcode == PcodeOp.INT_SEXT);
			if (!(v instanceof VarnodeOperation)) {
				return null;
			}
			op = (VarnodeOperation) v;
			opcode = op.getPCodeOp().getOpcode();
		}
		if (opcode != PcodeOp.LOAD) {
			return null;
		}
		Varnode[] inputValues = op.getInputValues();
		if (!inputValues[0].isConstant()) {
			return null;
		}
		AddressFactory addrFactory = program.getAddressFactory();
		if (addrFactory.getDefaultAddressSpace().getSpaceID() != inputValues[0].getOffset()) {
			// TableEntryAddress class assumes default address space for tables
			return null;
		}
		TableEntryAddress tableEntryAddress =
			TableEntryAddress.getTableEntryAddress(addrFactory, inputValues[1]);
		if (tableEntryAddress == null) {
			return null;
		}
		return new TableEntry(program, tableEntryAddress, op.getSize(), signExtend);
	}
}
