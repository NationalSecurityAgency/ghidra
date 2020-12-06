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
package ghidra.app.plugin.core.disassembler;

import java.util.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.app.util.PseudoDisassembler;
import ghidra.docking.settings.SettingsImpl;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.AddressSetPropertyMap;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class AddressTable {
	public static final int BILLION_CASES = 1024 * 1024 * 1024; // one billion cases for probability calculation
	public static final int TOO_MANY_ENTRIES = 1024 * 1024;     // too big of a table
	public static final int MINIMUM_SAFE_ADDRESS = 1024;       // default minimum address that should be considered an address

	private static final String TABLE_IN_PROGRESS_PROPERTY_NAME = "TableInProgress";
	private final static String NAME_PREFIX = "AddrTable";
	private final static String INDEX_PREFIX = "IndexToAddrTable";

	private Address topAddress;
	private Address[] tableElements;
	private Address topIndexAddress;
	private int indexLen;
	private int skipAmount;
	private boolean negativeTable = false;
	private int addrSize = 4;
	private boolean shiftedAddr;

	/**
	 * Define an address table
	 * 
	 * @param topAddress start address of the table
	 * @param tableElements pointer values from the table
	 * @param addrByteSize pointer data size
	 * @param skipAmount number of bytes to skip between address entries
	 * @param shiftedAddr if true an attempt will be made to utilize
	 *            shifted-pointers if the associated program data organization
	 *            specifies a pointer shift amount. The size of shifted-pointers
	 *            is also determined by the data organization and not the
	 *            specified addrByteSize (this is due to the fact that the
	 *            ShiftedAddressDataType is not a Pointer data type).
	 */
	public AddressTable(Address topAddress, Address[] tableElements, int addrByteSize,
			int skipAmount, boolean shiftedAddr) {
		this(topAddress, tableElements, null, 0, addrByteSize, skipAmount, shiftedAddr);
	}

	/**
	 * Create an address table with a secondary index into the table entries
	 * 
	 * @param topAddress start address of the table
	 * @param tableElements pointer values from the table
	 * @param topIndexAddress first address of the index into the address table
	 * @param indexLen length of the index
	 * @param addrByteSize size of address in bytes
	 * @param skipAmount distance between each entry in the address table
	 * @param shiftedAddr true if the address entries are shifted
	 */
	public AddressTable(Address topAddress, Address[] tableElements, Address topIndexAddress,
			int indexLen, int addrByteSize, int skipAmount, boolean shiftedAddr) {
		this.topAddress = topAddress;
		this.tableElements = tableElements;
		this.topIndexAddress = topIndexAddress;
		this.indexLen = indexLen;
		this.addrSize = addrByteSize;
		this.skipAmount = skipAmount;
		this.shiftedAddr = shiftedAddr;
	}

	/**
	 * @return the first address of the address table
	 */
	public Address getTopAddress() {
		return topAddress;
	}

	/**
	 * @return byte length of this table in memory
	 */
	public int getByteLength() {
		int length = tableElements.length * addrSize;

		// if there is an index table after this table
		if (topIndexAddress != null) {
			length += indexLen;
		}
		return length;
	}

	/**
	 * @return byte length of this table in memory
	 */
	public int getByteLength(int start, int end, boolean includeIndex) {
		int length = ((end - start) + 1) * addrSize;

		// if there is an index table after this table
		if (includeIndex && topIndexAddress != null) {
			length += indexLen;
		}
		return length;
	}

	/**
	 * @return number of address table entries
	 */
	public int getNumberAddressEntries() {
		return tableElements.length;
	}

	/**
	 * @return the actual found addresses table address entries
	 */
	public Address[] getTableElements() {
		return tableElements;
	}

	/**
	 * Index table Addresses .... Index offsets into the address table ....
	 * 
	 * @return top address of the index table following the address table
	 */
	public Address getTopIndexAddress() {
		return topIndexAddress;
	}

	/**
	 * @return number of entries in the index table if found
	 */
	public int getIndexLength() {
		return indexLen;
	}

	/**
	 * Get a generic name for the table
	 * 
	 * @param offset from the top of the table, normally 0
	 * @return a general name for the table based on the start and an optional
	 *         offset
	 */
	public String getTableName(int offsetLen) {
		return NAME_PREFIX + topAddress.addWrap(offsetLen * addrSize).toString();
	}

	/**
	 * Get a generic name for the index to the table
	 * 
	 * @param offsetLen offset from the top of the table
	 * @return a general name for the table based on the start and an optional
	 *         offset
	 */
	public String getIndexName(int offsetLen) {
		return INDEX_PREFIX + topAddress.addWrap(offsetLen * addrSize).toString();
	}

	/**
	 * Returns the prefix for a label to be created based on the address table
	 * element that points to it. The prefix consists of "AddrTable" followed by
	 * the address that is indicated as an offset from the beginning of the
	 * table followed by "Element". The element number can then be appended to
	 * this to create the label.
	 * 
	 * @param offsetLen the number of addresses the embedded prefix address
	 *            should be from the start of this address table.
	 * @return the prefix string for an address table element.
	 */
	public String getElementPrefix(int offsetLen) {
		return NAME_PREFIX + topAddress.addWrap(offsetLen * addrSize).toString() + "Element";
	}

	/**
	 * Make the table
	 *
	 * @param program
	 * @param start start index
	 * @param end end index (inclusive)
	 * @param autoLabel true if labels should be created on the table
	 * @return
	 */
	public boolean makeTable(Program program, int start, int end, boolean autoLabel) {
		return makeTable(program, start, end, true, autoLabel);
	}

	/**
	 * Make the table
	 *
	 * @param program
	 * @param start start index
	 * @param end end index (inclusive)
	 * @param createIndex don't create index if false
	 * @param autoLabel true if labels should be created on the table
	 * @return true if tablecreated else false
	 */
	public boolean makeTable(Program program, int start, int end, boolean createIndex,
			boolean autoLabel) {
		if (end > tableElements.length - 1) {
			end = tableElements.length - 1;
		}
		if (end < start) {
			end = start;
		}
		int len = end - start + 1;
		Address currentAddress = topAddress.addWrap(start * addrSize);

		// make sure this pointer is in the data type manager
		// since we are going to use it a lot
		DataType adt;

		//TODO: Do I need to do something special for the 3 byte pointers or will it know
		// how to make it automatically?
		DataTypeManager dtm = program.getDataTypeManager();
		if (shiftedAddr) {
			adt = ShiftedAddressDataType.dataType;
		}
		else if (addrSize == program.getDefaultPointerSize()) {
			adt = new PointerDataType(DataType.DEFAULT, dtm);
		}
		else {
			adt = new PointerDataType(DataType.DEFAULT, addrSize, dtm);
		}
		adt = dtm.resolve(adt, null);

		Address newAddress = currentAddress;

		// check to make sure there is no existing things overlapping the table or the index
		Listing listing = program.getListing();
		int totalLen = (len * addrSize + skipAmount);
		if (createIndex) {
			totalLen += getIndexLength();
		}
		if (!listing.isUndefined(currentAddress, currentAddress.addWrap(totalLen - 1))) {
			for (int k = 0; k < totalLen; k++) {
				Data data = listing.getDataContaining(currentAddress.addWrap(k));
				if (data == null ||
					(!(data.isPointer() || data.getDataType() instanceof Undefined) &&
						data.isDefined())) {
					return false;
				}
			}
		}

		//  make the pointers
		// TODO: add in the skip Length
		for (int j = 0; j < len; j++) {
			try { // make the data an address pointer
				DataUtilities.createData(program, newAddress, adt, adt.getLength(), false,
					DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			}
			catch (CodeUnitInsertionException exc) {
			}
			newAddress = newAddress.addWrap(addrSize + skipAmount);
		}

		if (createIndex) {
			createTableIndex(program);
		}

		if (autoLabel) {
			setLabels(program, currentAddress, len, start);
		}

		return true;
	}

	/**
	 * Create a switch table. If any new code is found while disassembling the
	 * table destinations, don't finish making the table!
	 *
	 * @param program
	 * @param start_inst
	 * @param opindex
	 * @param table
	 * @param flagNewCode
	 * @param monitor
	 *
	 * @return true if any new code was discovered!
	 */
	public boolean createSwitchTable(Program program, Instruction start_inst, int opindex,
			boolean flagNewCode, TaskMonitor monitor) {

		Listing listing = program.getListing();

		int tableSize = getNumberAddressEntries();
		Address tableAddr = getTopAddress();

		ArrayList<AddLabelCmd> switchLabelList = new ArrayList<>();
		AddLabelCmd tableNameLabel = null;

		FlowType ftype = start_inst.getFlowType();
		String tableName = (ftype.isCall() ? "callTable" : "switchTable");

		String comment = null;
		String caseName = "case_0x";
		if (isNegativeTable()) {
			tableName = "neg_" + tableName;
			caseName = "case_n0x";
			comment = "This table is a negative switch table,\r\nit indexes from the bottom";
		}

		// if there are already mnemonic references, then the switch stmt is already done.
		if (start_inst.getMnemonicReferences().length > 0) {
			return false;
		}

		// check if the instruction block creating the switch is in an executable memory block
		boolean instrBlockExecutable = false;
		MemoryBlock instrBlock = program.getMemory().getBlock(start_inst.getMinAddress());
		if (instrBlock != null && instrBlock.isExecute()) {
			instrBlockExecutable = true;
		}

		// if any new code is found while makeing the table, must
		//    not finish making the table and analyze the code!
		boolean newCodeFound = false;

		// Set flag if instruction is not in a function.
		//   We prefer switch tables to already be in a function.
		boolean notInAFunction =
			program.getFunctionManager().getFunctionContaining(start_inst.getMinAddress()) == null;

		// only mark as new code if there is not already a table in progress here
		boolean tableInProgress = checkTableInProgress(program, tableAddr);

		// create table size dw's after the jmp
		//   (could create as an array)
		try {
			// create a case label
			Symbol curSymbol = program.getSymbolTable().getPrimarySymbol(tableAddr);
			if (curSymbol != null && curSymbol.getName().startsWith("Addr")) {
				tableNameLabel = new AddLabelCmd(tableAddr, tableName, true, SourceType.ANALYSIS);
			}
			else {
				tableNameLabel = new AddLabelCmd(tableAddr, tableName, true, SourceType.ANALYSIS);
			}

			Address lastAddress = null;
			DataType ptrDT = program.getDataTypeManager().addDataType(
				PointerDataType.getPointer(null, addrSize), null);
			for (int i = 0; i < tableSize; i++) {
				Address loc = tableAddr.add(i * addrSize);
				try {
					try {
						program.getListing().createData(loc, ptrDT, addrSize);
					}
					catch (CodeUnitInsertionException e) {
						CodeUnit cu = listing.getCodeUnitAt(loc);
						if (cu instanceof Instruction) {
							break;
						}
						if (cu == null) {
							Msg.warn(this, "Couldn't get data at ");
							cu = listing.getDefinedDataContaining(loc);
							if (cu == null || cu instanceof Instruction) {
								break;
							}
							cu = ((Data) cu).getPrimitiveAt((int) loc.subtract(cu.getMinAddress()));
							if (cu == null) {
								break;
							}
						}
						if (!((Data) cu).isPointer()) {
							listing.clearCodeUnits(loc, loc.add(addrSize - 1), false);
							program.getListing().createData(loc, ptrDT, addrSize);
						}
					}
				}
				catch (CodeUnitInsertionException e) {
				}
				Data data = program.getListing().getDataAt(loc);
				if (data == null) {
					continue;
				}
				Address target = ((Address) data.getValue());
				if (target == null) {
					continue;
				}

				// make sure the pointer created is the same as the table target
				Address tableTarget = tableElements[i];
				if (tableTarget != null && !target.equals(tableTarget)) {
					data.removeValueReference(target);
					data.addValueReference(tableTarget, RefType.DATA);
					target = tableTarget;
				}

				// Don't allow the targets of the switch to vary widely
				MemoryBlock thisBlock = program.getMemory().getBlock(target);
				if (lastAddress != null) {
					try {
						long diff = lastAddress.subtract(target);
						if (diff > 1024 * 128) {
							break;
						}
					}
					catch (IllegalArgumentException e) {
						break;
					}
					MemoryBlock lastBlock = program.getMemory().getBlock(lastAddress);

					if (lastBlock == null || !lastBlock.equals(thisBlock)) {
						break;
					}
				}
				lastAddress = target;

				// check that the block we are in and the block targetted is executable
				if (instrBlockExecutable && thisBlock != null && !thisBlock.isExecute()) {
					break;
				}
				// disassemble the case
				if (program.getListing().getInstructionAt(target) == null || notInAFunction) {
					if (!tableInProgress) {
						newCodeFound = true;
					}
				}

				if (!flagNewCode || !newCodeFound) {
					// create a case label
					if (!ftype.isCall()) {
						AddLabelCmd lcmd = new AddLabelCmd(target,
							caseName + Integer.toHexString(i), true, SourceType.ANALYSIS);
						switchLabelList.add(lcmd);
					}

					// add a reference to the case
					start_inst.addMnemonicReference(target, ftype, SourceType.ANALYSIS);
					//program.getReferenceManager().addMemReference(start_inst.getMinAddress(), target, ftype, false, CodeUnit.MNEMONIC);
				}

				disassembleTarget(program, target, monitor);
			}

			// if we are in a function, fix up it's body
			if (!ftype.isCall()) {
				fixupFunctionBody(program, start_inst, monitor);
			}
		}
		catch (DataTypeConflictException e1) {
			return false;
		}

		// create the index array if this table has one
		if (getIndexLength() > 0) {
			createTableIndex(program);
		}

		if (comment != null) {
			program.getListing().setComment(topAddress, CodeUnit.EOL_COMMENT, comment);
		}

		if (flagNewCode && newCodeFound) {
			// make sure we didn't get any references on the mnemonic
			//  since more code must be found
			Reference refs[] = start_inst.getMnemonicReferences();
			for (Reference ref : refs) {
				start_inst.removeMnemonicReference(ref.getToAddress());
			}
			setTableInProgress(program, tableAddr);
			return true;
		}

		// get rid of the bookmark
		// TODO: this is probably not the best use of bookmarks to signal that the
		//       creation of a switch table is in progress.
		clearTableInProgress(program, tableAddr);

		// label the table if necessary
		labelTable(program, start_inst, switchLabelList, tableNameLabel);

		return false;
	}

	private void clearTableInProgress(Program program, Address tableAddr) {
		AddressSetPropertyMap list =
			program.getAddressSetPropertyMap(TABLE_IN_PROGRESS_PROPERTY_NAME);
		if (list == null) {
			return;
		}
		list.remove(tableAddr, tableAddr);
	}

	private void setTableInProgress(Program program, Address tableAddr) {
		AddressSetPropertyMap list =
			program.getAddressSetPropertyMap(TABLE_IN_PROGRESS_PROPERTY_NAME);
		if (list == null) {
			try {
				list = program.createAddressSetPropertyMap(TABLE_IN_PROGRESS_PROPERTY_NAME);
			}
			catch (DuplicateNameException e) {
				list = program.getAddressSetPropertyMap(TABLE_IN_PROGRESS_PROPERTY_NAME);
			}
		}
		if (list == null) {
			return;
		}
		list.add(tableAddr, tableAddr);
	}

	private boolean checkTableInProgress(Program program, Address tableAddr) {
		AddressSetPropertyMap list =
			program.getAddressSetPropertyMap(TABLE_IN_PROGRESS_PROPERTY_NAME);
		if (list == null) {
			return false;
		}
		return list.contains(tableAddr);
	}

	public void labelTable(Program program, Instruction start_inst,
			ArrayList<AddLabelCmd> switchLabelList, AddLabelCmd tableNameLabel) {
		// check if the table is already labeled
		Symbol syms[] = program.getSymbolTable().getSymbols(getTopAddress());
		for (Symbol sym : syms) {
			if (sym.getName(false).startsWith(tableNameLabel.getLabelName())) {
				return;
			}
		}

		long tableNumber = 0;
		boolean needTableNumber = false;
		boolean succeed = false;
		String oldName = tableNameLabel.getLabelName();
		Namespace space = null;
		// not putting switch into functions anymore
		//    program.getSymbolTable().getNamespace(start_inst.getMinAddress());
		try {
			space = program.getSymbolTable().createNameSpace(null,
				"switch_" + start_inst.getMinAddress(), SourceType.ANALYSIS);
		}
		catch (DuplicateNameException e) {
			// just go with default space
		}
		catch (InvalidInputException e) {
			// just go with default space
		}
		Symbol oldSym = program.getSymbolTable().getPrimarySymbol(tableNameLabel.getLabelAddr());
		if (oldSym != null && oldSym.getSource() == SourceType.ANALYSIS &&
			oldSym.getName().startsWith("Addr")) {
			oldSym.delete();
		}
		do {
			tableNameLabel.setNamespace(space);
			succeed = tableNameLabel.applyTo(program);
			if (succeed) {
				break;
			}
			tableNumber++;
			needTableNumber = true;
			//tableNameLabel.setLabelName(oldName + "_" + Long.toHexString(tableNumber));
			tableNameLabel.setLabelName(oldName + "_" + tableNumber);
		}
		while (tableNumber < 20);

		if (needTableNumber && tableNumber >= 20) {
			tableNumber = this.topAddress.getOffset();
			tableNameLabel.setLabelName(oldName + "_" + Long.toHexString(tableNumber));
		}

		// make sure the reference is associated with this symbol
		Symbol s = program.getSymbolTable().getGlobalSymbol(tableNameLabel.getLabelName(),
			tableNameLabel.getLabelAddr());
		for (int op = 0; op < start_inst.getNumOperands(); op++) {
			Reference fromRefs[] = start_inst.getOperandReferences(op);
			for (Reference fromRef : fromRefs) {
				if (fromRef.getToAddress().equals(tableNameLabel.getLabelAddr())) {
					program.getReferenceManager().setAssociation(s, fromRef);
					break;
				}
			}
		}

		// label the index array if this table has one
		if (getIndexLength() > 0) {
			AddLabelCmd lcmd =
				new AddLabelCmd(getTopIndexAddress(), "switchIndex", true, SourceType.ANALYSIS);
			switchLabelList.add(lcmd);
		}

		for (AddLabelCmd lcmd : switchLabelList) {
			lcmd.setNamespace(space);
			if (needTableNumber) {
				lcmd.setLabelName(lcmd.getLabelName() + "_" + Long.toHexString(tableNumber));
			}
			oldSym = program.getSymbolTable().getPrimarySymbol(lcmd.getLabelAddr());
			if (oldSym != null && oldSym.getSource() == SourceType.ANALYSIS &&
				oldSym.getName().startsWith("Addr")) {
				oldSym.delete();
			}
			lcmd.applyTo(program);
		}
	}

	/**
	 * Fixup the function body if there is a function defined here.
	 *
	 * @param program program we are in
	 * @param start_inst start instruction of the jump table
	 * @param table
	 * @param monitor monitor to output results.
	 */
	public void fixupFunctionBody(Program program, Instruction start_inst, TaskMonitor monitor) {
		Function func =
			program.getFunctionManager().getFunctionContaining(start_inst.getMinAddress());
		if (func == null) {
			return;
		}

		if (start_inst.getFlowType().isCall()) {
			return;
		}

		// compute the new body, and add in the body of the table
		AddressSetView oldBody = func.getBody();
		Address entryPoint = func.getEntryPoint();
		AddressSetView funcBody = null;
		try {
			funcBody = CreateFunctionCmd.getFunctionBody(program, entryPoint);
			funcBody = funcBody.union(oldBody);
			AddressSetView body = funcBody.union(getTableBody());
			Iterator<Function> fiter =
				program.getFunctionManager().getFunctionsOverlapping(funcBody);
			while (fiter.hasNext()) {
				Function function = fiter.next();
				if (function.getEntryPoint().equals(func.getEntryPoint())) {
					continue;
				}
				body = body.subtract(function.getBody());
			}
			if (!oldBody.hasSameAddresses(body)) {
				func.setBody(body);
			}
		}
		catch (OverlappingFunctionException e) {

			try {
				funcBody = CreateFunctionCmd.getFunctionBody(monitor, program, entryPoint);
				funcBody = funcBody.union(oldBody);
				AddressSetView body = funcBody.union(getTableBody());
				if (!oldBody.hasSameAddresses(body)) {
					func.setBody(body);
				}
			}
			catch (OverlappingFunctionException e1) {
				// failed, try just with the function body, no address table
				try {
					func.setBody(funcBody);
				}
				catch (OverlappingFunctionException e2) {
				}
			}
			catch (CancelledException e3) {
			}
		}
	}

	/**
	 * Create the index array for this table if it has an index
	 */
	public void createTableIndex(Program program) {
		Listing listing = program.getListing();

		// make the index array of bytes if there is one
		if (getTopIndexAddress() != null) {
			ByteDataType bdt = new ByteDataType();
			ArrayDataType arraydt = new ArrayDataType(bdt, getIndexLength(), bdt.getLength());
			try {
				listing.createData(getTopIndexAddress(), arraydt, getIndexLength());
			}
			catch (CodeUnitInsertionException e) {
			}
		}
	}

	public boolean isFunctionTable(Program program, int offset) {
		PseudoDisassembler pdis = new PseudoDisassembler(program);
		ArrayList<Address> disassembleList = new ArrayList<>();

		// get the set of addresses that are marked executable
		AddressSet execSet = getExecuteSet(program.getMemory());

		//  make the pointers
		//
		for (int j = offset; j < tableElements.length; j++) {
			Address testAddr = tableElements[j];
			if (testAddr == null) {
				return false;
			}
			if (execSet != null && !execSet.contains(testAddr)) {
				return false;
			}
			if (pdis.isValidCode(testAddr)) {
				disassembleList.add(testAddr);
			}
			if (tableContains(testAddr)) {
				disassembleList.add(testAddr);
			}
		}
		if (disassembleList.size() == tableElements.length - offset) {
			return true;
		}
		return false;
	}

	public ArrayList<Address> getFunctionEntries(Program program, int offset) {
		PseudoDisassembler pdis = new PseudoDisassembler(program);
		ArrayList<Address> disassembleList = new ArrayList<>();

		// get the set of addresses that are marked executable
		AddressSet execSet = getExecuteSet(program.getMemory());

		Listing listing = program.getListing();

		//  check all addresses for valid pointers
		//
		for (int j = offset; j < tableElements.length; j++) {
			Address testAddr = tableElements[j];
			if (testAddr == null) {
				return disassembleList;
			}
			if (execSet != null && !execSet.contains(testAddr)) {
				continue;
			}
			// if it is already an instruction, assume it is valid.

			Instruction instr = listing.getInstructionContaining(testAddr);
			if (instr != null) {
				// doesn't start the instruction, not valid
				if (instr.getMinAddress().equals(testAddr)) {
					disassembleList.add(testAddr);
				}
				continue;
			}
			if (listing.getDefinedDataContaining(testAddr) != null) {
				continue;
			}
			if (pdis.isValidCode(testAddr)) {
				disassembleList.add(testAddr);
				continue;
			}
		}
		return disassembleList;
	}

	private AddressSet getExecuteSet(Memory memory) {
		AddressSet set = new AddressSet();
		MemoryBlock blocks[] = memory.getBlocks();
		for (MemoryBlock block : blocks) {
			if (block.isExecute()) {
				set.addRange(block.getStart(), block.getEnd());
			}
		}
		return (set.isEmpty() ? null : set);
	}

	/**
	 * Disassemble all the entries in the table
	 */
	public boolean disassemble(Program program, Instruction instr, TaskMonitor monitor) {
		// disassemble the table
		// pull out the current context so we can flow anything that needs to flow
		ProgramContext programContext = program.getProgramContext();
		Register baseContextRegister = programContext.getBaseContextRegister();
		RegisterValue switchContext = null;
		if (baseContextRegister != null) {
			// Use disassembler context based upon context register value from switch location
			switchContext =
				programContext.getRegisterValue(baseContextRegister, instr.getMinAddress());
		}

		Listing listing = program.getListing();
		boolean gotNewCode = false;
		for (Address tableElement : tableElements) {
			Address caseStart = tableElement;

			// if conflict skip case
			if (listing.getUndefinedDataAt(caseStart) == null) {
				continue;
			}
			if (switchContext != null) {
				try {
					// Use disassembler context based upon context register value from function entry point
					RegisterValue curContext =
						programContext.getRegisterValue(baseContextRegister, caseStart);
					if (curContext != null) {
						curContext = curContext.combineValues(switchContext);

						// lay down the new merged context
						programContext.setRegisterValue(caseStart, caseStart, curContext);
					}
					else {
						programContext.setRegisterValue(caseStart, caseStart, switchContext);
					}
				}
				catch (ContextChangeException e) {
					// This can occur when two or more threads are working on the same function
					continue;
				}
			}

			gotNewCode |= !disassembleTarget(program, caseStart, monitor).isEmpty();
		}

		return gotNewCode;
	}

	private AddressSet disassembleTarget(Program program, Address target, TaskMonitor monitor) {
		// DisassembleCmd will align to the addresses, but need the correct context set based on this address
		RegisterValue regContext =
			PseudoDisassembler.getTargetContextRegisterValueForDisassembly(program, target);
		DisassembleCommand cmd = new DisassembleCommand(target, null, true);
		cmd.setInitialContext(regContext);
		cmd.applyTo(program, monitor);
		return cmd.getDisassembledAddressSet();
	}

	/**
	 * Test if this table has an element that points into the table.
	 */
	private boolean tableContains(Address testAddr) {
		Address end = topAddress.add(this.getByteLength());
		AddressRange range = new AddressRangeImpl(topAddress, end);

		return range.contains(testAddr);
	}

	private void setLabels(Program program, Address currentAddress, int len, int offset) {
		SymbolTable symbolTable = program.getSymbolTable();

		try {
			// Label table
			Symbol sym = symbolTable.getPrimarySymbol(currentAddress);

			if (sym == null || sym.isDynamic()) {
				symbolTable.createLabel(currentAddress, getTableName(offset), SourceType.ANALYSIS);
			}
			else {
				if (sym.getName().regionMatches(0, "AddrTable", 0, 9)) {
					sym.setName(getTableName(offset), SourceType.ANALYSIS);
				}
			}

			// Label table elements
//			Symbol elementSym;
//			for (int elementNum = 0; elementNum < len; elementNum++) {
//				// test to see if there is already an existing label - if not, then name table elements
//				elementSym = symbolTable.getPrimarySymbol(tableElements[elementNum+offset]);
//				String elementPrefix = getElementPrefix(offset);
//				String elementNumString = Integer.toString(elementNum, 10);
//				String elementName = elementPrefix + elementNumString;
//				if(elementSym == null || elementSym.isDynamic()) {
//					symbolTable.createSymbol(tableElements[elementNum+offset],elementName, SourceType.ANALYSIS);
//				}
//				else {
////					if(!elementSym.isUserDefined()) {
////						elementSym.setName(elementName);
////					}
//					String currentName = elementSym.getName();
//					if (currentName.startsWith("AddrTable")) {
//						if (currentName.startsWith(elementPrefix)) {
//							String suffix = currentName.substring(elementPrefix.length());
//							if (!hasNumInSuffix(suffix, elementNumString)) {
//								if (elementSym.getName().length() < 64) {
//									elementSym.setName(elementSym.getName()+"_"+ elementNumString, SourceType.ANALYSIS);
//								}
//							}
//						}
//						else {
//							elementSym.setName(elementName, SourceType.ANALYSIS);
//						}
//					}
//				}
//			}
			// Label table index if there is one
			if (getTopIndexAddress() != null) {
				Symbol indexSym;

				indexSym = symbolTable.getPrimarySymbol(getTopIndexAddress());
				if (indexSym == null || indexSym.isDynamic()) {
					symbolTable.createLabel(getTopIndexAddress(), getIndexName(offset),
						SourceType.ANALYSIS);
				}
				else {
					if ((indexSym.getName().regionMatches(0, "Index", 0, 5))) {
						indexSym.setName(getIndexName(offset), SourceType.ANALYSIS);
					}
				}
			}
		}
		catch (DuplicateNameException exc) {
		}
		catch (InvalidInputException exc) {
		}
	}

	public String getTableTypeString(Memory memory) {
		Address addr = tableElements[0];
		DumbMemBufferImpl memBuf = new DumbMemBufferImpl(memory, addr);
		StringDataType sdt = new StringDataType();

		String str;
		try {
			str = getByteCodeString(memBuf, null, null, addrSize) + " (" +
				sdt.getValue(memBuf, SettingsImpl.NO_SETTINGS, addrSize) + ")";
		}
		catch (AddressOutOfBoundsException e) {
			str = "";
		}
		return str;
	}

	private String getByteCodeString(DumbMemBufferImpl memBuf, Object object, Object object2,
			int length) {
		StringBuffer bytes = new StringBuffer();

		for (int ii = 0; ii < length; ii++) {
			if (ii != 0) {
				bytes.append(" ");
			}
			String hex;
			try {
				hex = Integer.toHexString(memBuf.getByte(ii));
			}
			catch (MemoryAccessException e) {
				hex = "00";
			}
			if (hex.length() == 1) {
				bytes.append("0");
			}
			if (hex.length() > 2) {
				bytes.append(hex.substring(hex.length() - 2));
			}
			else {
				bytes.append(hex);
			}
		}
		return bytes.toString();
	}

	/**
	 * Get an Address Table Object (always uses shifted addresses, if specified
	 * by language)
	 *
	 * @param program
	 * @param topAddr starting adddress of the table
	 * @param checkExisting check for existing instructions, data, or labels
	 * @param minimumTableSize minimum table size
	 * @param alignment only return a table for addresses that fall on alignment
	 *            in bytes
	 * @param minAddressOffset minimum value to be considered a pointer,
	 *            dangerous to go below 1024 for some things
	 * @param useRelocationTable use relocationTable for relocatablePrograms to
	 *            check for valid pointers
	 * @return null if no valid table exists at the topAddr
	 */
	public static AddressTable getEntry(Program program, Address topAddr, TaskMonitor monitor,
			boolean checkExisting, int minimumTableSize, int alignment, int skipAmount,
			long minAddressOffset, boolean useRelocationTable) {
		return getEntry(program, topAddr, monitor, checkExisting, minimumTableSize, alignment,
			skipAmount, minAddressOffset, true, false, useRelocationTable);
	}

	/**
	 * Get an Address Table Object (allows you to specify whether to use shifted
	 * addresses or not)
	 *
	 * @param program
	 * @param topAddr starting adddress of the table
	 * @param checkExisting check for existing instructions, data, or labels
	 * @param minimumTableSize minimum table size
	 * @param alignment only return a table for addresses that fall on alignment
	 *            in bytes
	 * @param skipAmount number of bytes to skip between address entries
	 * @param minAddressOffset minimum value to be considered a pointer,
	 *            dangerous to go below 1024 for some things
	 * @param checkForIndex true if check for a single byte index table after
	 *            the address table
	 * @param useRelocationTable true to only consider pointers that are in the
	 *            relocationTable for relocatable programs
	 * @return null if no valid table exists at the topAddr
	 */
	public static AddressTable getEntry(Program program, Address topAddr, TaskMonitor monitor,
			boolean checkExisting, int minimumTableSize, int alignment, int skipAmount,
			long minAddressOffset, boolean useShiftedAddressesIfNecessary, boolean checkForIndex,
			boolean useRelocationTable) {
		Memory memory = program.getMemory();
		Listing listing = program.getListing();

		int addressShiftAmount;
		boolean shiftedAddresses;
		if (useShiftedAddressesIfNecessary) {
			addressShiftAmount =
				program.getDataTypeManager().getDataOrganization().getPointerShift();
			shiftedAddresses = addressShiftAmount != 0;
		}
		else {
			shiftedAddresses = false;
			addressShiftAmount = 0;
		}

// TODO: need to specify the size of ptrs in this processor....

		// if the address doesn't start on the processors instruction alignment
		//   it shouldn't be the start of a table
		int langAlignment = program.getLanguage().getInstructionAlignment();
		if (alignment < 1 && langAlignment != 1) {
			alignment = langAlignment;
		}
		if (alignment < 1 || alignment > 8) {
			alignment = 1;
		}
		if (topAddr.getOffset() % alignment != 0) {
			return null;
		}

		AddressRange range = memory.getRangeContaining(topAddr);
		if (range == null) {
			return null;
		}

		ArrayList<Address> arrayElements = new ArrayList<>();
		HashSet<Address> arrayEntries = new HashSet<>();

		int count = 0;
		Address currentAddr = topAddr;
		int addrSize = program.getDefaultPointerSize();

		AddressSet pointerSet = new AddressSet();  // set where address pointers are - minus skipAmount

		while (!monitor.isCancelled() && range.contains(currentAddr)) {
			try {
				// get the value in address form of the bytes at address a
				long addrLong = 0;
				//For the 24 bit programs we see now, they all have a 00 pad after the 3 byte addr
				// so we have to treat the searched addrs as 4 byte, when they are created, they are 3 byte
				if (addrSize == 3) {
					int addrInt = memory.getInt(currentAddr);
					addrLong = addrInt & 0xffffffffL;
				}
				if (addrSize == 4) {
					int addrInt = memory.getInt(currentAddr);
					if (shiftedAddresses) {
						addrLong = ((addrInt << addressShiftAmount) & 0xffffffffL);
					}
					else {
						addrLong = addrInt & 0xffffffffL;
					}

				}
				else if (addrSize == 8) {
					addrLong = memory.getLong(currentAddr);
				}
				Address testAddr = currentAddr.getNewAddress(addrLong);

				if (testAddr.equals(Address.NO_ADDRESS)) {
					break;
				}

				// if this shouldn't be considered an address because it is too low in memory!
				if (addrLong > 0 && addrLong < minAddressOffset) {
					break;
				}

				// test that the value isn't 0
				//    May be bad if an address table has a 0 in it, but normally
				//    0 is not found in memory anyway, so better to be conservative
				if (addrLong == 0) {
					break;
				}

				// if the address isn't valid for this processors alignment
				if (testAddr.getOffset() % alignment != 0) {
					break;
				}

				// See if the tested address is contained in memory
				if (!memory.contains(testAddr)) {
//					if (addrSize == 8) {  // don't try to look up in database, it polutes the key lookup in the DB
//						break;
//					}
//
//					// TODO: what is this doing?  doesn't seem like anything, always breaks!
//					Symbol syms[] = program.getSymbolTable().getSymbols(testAddr);
//					if (syms == null || syms.length == 0 || syms[0].getSource() == SourceType.DEFAULT) {
//						break;
//					}
					break;
				}

				// If the program is relocatable, and this address is not one of the relocations
				//   can't be a pointer
				if (useRelocationTable && !isValidRelocationAddress(program, currentAddr)) {
					break;
				}

				// if there is a ref in the middle of the table, then isn't a table, stops here...
				if (count > 1 &&
					program.getReferenceManager().getReferenceCountTo(currentAddr) > 0) {
					break;
				}

				// also check what the address pointer points to, if the thing
				//   existing there doesn't jibe with the pointer, don't do it.
				if (checkExisting && checkForCollisionAtTarget(program, testAddr)) {
					break;
				}

				// add the valid address to the list and increment past it
				arrayElements.add(testAddr);
				arrayEntries.add(currentAddr);
				pointerSet.add(currentAddr, currentAddr.add(addrSize - 1));
				currentAddr = currentAddr.add(addrSize + skipAmount);

				count++;
			}
			catch (MemoryAccessException e) {
				break;
			}
			catch (AddressOutOfBoundsException e) {
				break;
			}
		}

		// if table too small, don't even check later...
		if (count < minimumTableSize) {
			return null;
		}

		// Any reference or symbol breaks the address table.

		// Find the next reference after this address and adjust the table size
		//  if needed.
		Address nextSymAddr = null;
		try {
			AddressIterator addrIter =
				program.getReferenceManager().getReferenceDestinationIterator(topAddr.add(1), true);
			nextSymAddr = addrIter.next();
		}
		catch (AddressOutOfBoundsException e) {
			// ignore, no nextSymAddr
		}

		// Find the next symbol after this address and adjust the table size
		//  if needed.
		Address endAddr = topAddr.add((count * (addrSize + skipAmount)));
		if (nextSymAddr != null && nextSymAddr.compareTo(endAddr) < 0) {
			count = (int) (nextSymAddr.subtract(topAddr) / (addrSize + skipAmount));
		}
		if (count < minimumTableSize) {
			return null;
		}

		// iterate over defined codeunits in pointerSet
		if (checkExisting) {
			CodeUnit codeUnitContaining = listing.getCodeUnitContaining(topAddr);
			if (codeUnitContaining != null) {
				if (!codeUnitContaining.getMinAddress().equals(topAddr)) {
					return null;
				}
				// if instruction at topAddr, then this not a good table, data is OK
				if (codeUnitContaining instanceof Instruction) {
					return null;
				}
			}

			// get next instruction, restrict table to before instruction
			Instruction instructionAfter = listing.getInstructionAfter(topAddr);
			endAddr = topAddr.add((count * (addrSize + skipAmount)));
			if (instructionAfter != null) {
				Address iAddr = instructionAfter.getMinAddress();
				if (iAddr.compareTo(endAddr) < 0) {
					count = (int) (iAddr.subtract(topAddr) / (addrSize + skipAmount));
				}
			}
			if (count < minimumTableSize) {
				return null;
			}

			// look for defined data that isn't already a pointer that doesn't align with
			//  the tables pointer starts
			endAddr = topAddr.add((count * (addrSize + skipAmount)) - 1);
			DataIterator definedData = listing.getDefinedData(topAddr, true);
			while (definedData.hasNext()) {
				Data data = definedData.next();
				// no data found or past end of table
				Address dataAddr = data.getMinAddress();
				if (data == null || dataAddr.compareTo(endAddr) > 0) {
					break;
				}
				// data found at start of pointer
				if (arrayEntries.contains(dataAddr)) {
					// if pointer, OK
					if (data.isPointer()) {
						continue;
					}
				}
				// data intersects, calculate valid entries and stop looking
				if (pointerSet.intersects(dataAddr, data.getMaxAddress())) {
					count = (int) (dataAddr.subtract(topAddr) / (addrSize + skipAmount));
					break;
				}
			}

		}

		if (count < minimumTableSize) {
			return null;
		}

		currentAddr = topAddr.add(count * (addrSize + skipAmount));

		Address[] tableElements = new Address[count];
		arrayElements.subList(0, count).toArray(tableElements);
		arrayElements = null;
		// Warning: arrayElements is no longer valid after this!

		// Don't check if the table is too large
		// TODO: This is not statistically correct.
		//       Only small tables should be found, and the probability that a run of
		//       random bytes after a table should be set to some large number.
		//       Fix for now by not searching, unless in address table searcher.
		if (checkForIndex && count < 128) {
			// figure out the address immediately after the table
			Address topIndexAddr = currentAddr;
			// check for tableElement that is closest to the bottom of the address table
			// to determine the max size of the index array
			long maxIndexSize = 100000;
			for (Address tableElement : tableElements) {
				long temp = tableElement.subtract(topIndexAddr);
				// this is the case where at least one of the elements is before the table
				// make temp the size of the rest of the memory segment - if it is larger than the
				// current maxIndexSize it will get overwritten in the next if statement
				if (temp < 0) {
					MemoryBlock block = memory.getBlock(topIndexAddr);
					if (block == null) {
						temp = 0;
					}
					else {
						temp = block.getEnd().subtract(topIndexAddr);
					}
				}
				if (temp < maxIndexSize) {
					maxIndexSize = temp;
				}
			}

			//search for index after the table
			int numIndexBytes = 0;
			int numZeroBytes = 0;

			boolean isIndex = true;
			if (maxIndexSize == 0) {
				isIndex = false;
			}

			while ((isIndex) && (numIndexBytes < maxIndexSize)) {
				byte b;
				try {
					b = memory.getByte(currentAddr);
				}
				catch (MemoryAccessException e) {
					break;
				}

				if ((b >= 0) && (b < count)) {
					numIndexBytes++;
					if (b == 0) {
						numZeroBytes++;
					}
				}
				else {
					isIndex = false;
				}
				currentAddr = currentAddr.next();
			}
			// I added the check for no more than 100 zeros for the cases where there are huge runs of zeros
			// followed by a valid index value - not sure if 100 is to big or too small
			if ((numIndexBytes >= count) && (numZeroBytes < numIndexBytes) &&
				(numZeroBytes < 100)) {
				return new AddressTable(topAddr, tableElements, topIndexAddr, numIndexBytes,
					addrSize, skipAmount, shiftedAddresses);
			}
		}
		return new AddressTable(topAddr, tableElements, null, 0, addrSize, skipAmount,
			shiftedAddresses);
	}

	/**
	 * Check for collision or inconsistencies at the target address
	 *
	 * @return true if there is some inconsistency where this shouldn't be
	 *         considered a pointer
	 */
	private static boolean checkForCollisionAtTarget(Program program, Address testAddr) {

		boolean allowOffcutCode = PseudoDisassembler.hasLowBitCodeModeInAddrValues(program);
		// if the pointer is into the middle of code
		Instruction instr = program.getListing().getInstructionContaining(testAddr);
		if (instr == null) {
			return false;
		}
		// in the middle of an instruction
		if (isOffcutReference(testAddr, instr.getMinAddress(), allowOffcutCode)) {
			return true;
		}
		// instruction has a fall from
		if (instr.getFallFrom() != null) {
			return true;
		}
		// check in the middle of a function
		Function func = program.getFunctionManager().getFunctionContaining(testAddr);
		if (func != null && isOffcutReference(testAddr, func.getEntryPoint(), allowOffcutCode)) {
			// check all the references to this place, If they are all data
			// ptrs, and non-computed Jumps references
			// then it could be a shared Return routine. Let it go through
			ReferenceIterator referencesTo =
				program.getReferenceManager().getReferencesTo(testAddr);
			for (Reference reference : referencesTo) {
				RefType referenceType = reference.getReferenceType();
				if (referenceType.isData()) {
					return false;
				}
				if (referenceType.isJump() && !referenceType.isComputed()) {
					return false;
				}
			}
			return true;
		}

		return false;
	}

	private static boolean isOffcutReference(Address testAddr, Address target,
			boolean processorUsesLowBitForCode) {
		if (testAddr.equals(target)) {
			return false;
		}
		// allow 1 byte offcut
		if (processorUsesLowBitForCode && target.isSuccessor(testAddr)) {
			return false;
		}
		return true;
	}

	/**
	 *
	 * @param program to check
	 * @param oneInNumberOfCases 1 in this number of cases
	 * @return the number of valid runs of pointers to achieve a ( 1 in
	 *         numberOfCases)
	 */
	public static int getThresholdRunOfValidPointers(Program program, long oneInNumberOfCases) {
		// find the valid blocks
		MemoryBlock[] blocks = program.getMemory().getBlocks();
		double byteCount = 0;
		for (MemoryBlock memoryBlock : blocks) {
			if (memoryBlock.getStart().getAddressSpace().isOverlaySpace()) {
				continue;
			}
			byteCount += memoryBlock.getSize();
		}

		// get the size of the space
		double bitSize =
			program.getLanguage().getDefaultCompilerSpec().getDataOrganization().getPointerSize() *
				8;
		double byteSize = Math.ceil(Math.pow(2.0, bitSize));

		if (byteCount >= byteSize) {
			return TOO_MANY_ENTRIES;  // Need many in a row!
		}

		double threshold = 1.0 / (oneInNumberOfCases);  // 1 in a billion chance

		// calculate the number of items needed in a row
		double numberInRowNeeded = Math.ceil(Math.log(threshold) / Math.log(byteCount / byteSize));

		return (int) numberInRowNeeded;
	}

	/**
	 * Check if the address is in the Relocation table. This only counts for
	 * relocatable programs. Every address should be in the relocation table.
	 * 
	 * @param target location to check
	 * @return
	 */
	private static boolean isValidRelocationAddress(Program program, Address target) {
		// If the program is relocatable, and this address is not one of the relocations
		//   can't be a pointer
		RelocationTable relocationTable = program.getRelocationTable();
		if (relocationTable.isRelocatable()) {
			// if it is relocatable, then there should be no pointers in memory, other than relacatable ones
			if (relocationTable.getSize() > 0 && relocationTable.getRelocation(target) == null) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Get the address set that represents the addresses consumed by this table.
	 *
	 * @return address set representing the bytes that make up the table.
	 */
	public AddressSetView getTableBody() {
		AddressSet set = new AddressSet();

		set.addRange(topAddress, topAddress.add(getByteLength() - 1));

		if (topIndexAddress != null) {
			set.addRange(topIndexAddress, topIndexAddress.add(indexLen - 1));
		}
		return set;
	}

	/**
	 * Set whether this is a negatively indexed table
	 *
	 * @param isNegative true if is negatively indexed table
	 */
	public void setNegativeTable(boolean isNegative) {
		negativeTable = isNegative;
	}

	/**
	 * @return true if this is a negatively indexed table
	 */
	public boolean isNegativeTable() {
		return negativeTable;
	}

	/**
	 * Change table entry i to a new target address
	 */
	public void changeEntry(int i, Address address) {
		if (i < 0 || i >= this.tableElements.length) {
			return;
		}
		tableElements[i] = address;
	}

	/**
	 * Truncate the table to tableLen entries
	 *
	 * @param tableLen
	 */
	public void truncate(int tableLen) {
		Address[] newTable = new Address[tableLen];
		System.arraycopy(tableElements, 0, newTable, 0, tableLen);

		tableElements = newTable;
	}
}
