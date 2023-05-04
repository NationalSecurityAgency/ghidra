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
package classrecovery;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class Vtable {

	private static final String VTABLE_LABEL = "vtable";

	Program program;
	Address vtableAddress;
	Boolean isSpecial = null;
	GccTypeinfoRef typeinfoRef = null;
	Address typeinfoRefAddress = null;
	GccTypeinfo typeinfo = null;
	Boolean hasVfunctions = null;
	Integer numVfunctions = null;
	Long topOffsetValue = null;
	Address vfunctionTop = null;
	Address typeinfoAddress = null;

	Boolean isPrimary = null;
	Boolean isConstruction = null;
	List<Vtable> internalVtables = new ArrayList<Vtable>();
	List<Address> relatedMainVtables = new ArrayList<Address>();
	boolean inExternalMemory;
	Boolean isValid = true;

	Namespace typeinfoNamespace = null;
	Namespace classNamespace = null;
	Integer length = null;
	Vtable primaryVtable = null;
	int defaultPointerSize;
	SymbolTable symbolTable;
	ExtendedFlatProgramAPI extendedFlatAPI;
	TaskMonitor monitor;
	GlobalNamespace globalNamespace;
	FunctionManager functionManager;
	DataTypeManager dataTypeManager;
	Listing listing;

	

	public Vtable(Program program, Address vtableAddress, GccTypeinfoRef typeinfoRef, boolean isSpecial, boolean inExternalMemory,
			Vtable primaryVtable, Boolean isConstruction, TaskMonitor monitor)
			throws CancelledException {

		this.program = program;
		this.vtableAddress = vtableAddress;
		this.typeinfoRef = typeinfoRef;
		this.isSpecial = isSpecial;
		this.inExternalMemory = inExternalMemory;
		this.primaryVtable = primaryVtable;
		this.isConstruction = isConstruction;
		this.monitor = monitor;
		this.typeinfoRefAddress = typeinfoRef.getAddress();
		this.typeinfo = (GccTypeinfo) typeinfoRef.getReferencedTypeinfo();
		this.typeinfoNamespace = typeinfo.getNamespace();

		AddressSpace addressSpace = vtableAddress.getAddressSpace();
		defaultPointerSize = addressSpace.getPointerSize();
		symbolTable = program.getSymbolTable();
		extendedFlatAPI = new ExtendedFlatProgramAPI(program, monitor);
		globalNamespace = (GlobalNamespace) program.getGlobalNamespace();
		functionManager = program.getFunctionManager();
		dataTypeManager = program.getDataTypeManager();
		listing = program.getListing();
	
		setup();
	}
	
	public Vtable(Program program, Address vtableAddress, GccTypeinfoRef typeinfoRef, boolean isSpecial, boolean inExternalMemory, TaskMonitor monitor)
			throws CancelledException {
		this(program, vtableAddress, typeinfoRef, isSpecial, inExternalMemory, null, null, monitor);
	}

	public Vtable(Program program, Address vtableAddress, GccTypeinfoRef typeinfoRef, boolean isSpecial, boolean inExternalMemory, boolean isConstruction,
			TaskMonitor monitor) throws CancelledException {
		this(program, vtableAddress, typeinfoRef, isSpecial, inExternalMemory, null, isConstruction, monitor);
	}

	protected void setup() throws CancelledException  {

		checkValidTop();

		if (!isValid) {
			return;
		}

		setTopOffsetValue();

		if (!isValid) {
			return;
		}

		setIsInternalVtable();

		if (!isValid) {
			return;
		}

		figureOutNamespace();
		
		setHasVfunctions();

		if (!isValid) {
			return;
		}

		// setIsConstructionVtable();

		if (!isValid) {
			return;
		}

		setLength();

		if (!isValid) {
			return;
		}
		
		try {
			applyVtableData();
		} catch (Exception e) {
			isValid = false;
		}

		findInternalVtables();
	}

	public boolean equals(Vtable vtable) {
		return vtable.getAddress().equals(vtableAddress);
	}

	private void checkValidTop() {

		// check for existing vtable name - if has a non-default label that isn't vtable
		// then assume not valid
		Symbol symbol = symbolTable.getPrimarySymbol(vtableAddress);
		if (symbol != null && symbol.getSource() != SourceType.DEFAULT) {
			if (symbol.getName().contains(VTABLE_LABEL)) {
				isValid = true;
				return;
			}
			isValid = false;
			return;
		}

		// for ones with no symbol or default symbol check for long value/non address at
		// top
		// if is an address not valid
		// if is not an address may be valid - will need further checks in other methods
		Address referencedAddress = getReferencedAddress(vtableAddress);
		if (referencedAddress != null) {
			isValid = false;
			return;
		}
		// May or may not be valid but so far valid
		isValid = true;
	}

	public Address getAddress() {
		return vtableAddress;
	}

	public boolean isExternal() {
		return inExternalMemory;
	}

	public boolean isValid() {
		return isValid;
	}


	public Address getTypeinfoRefAddress() {
		return typeinfoRef.getAddress();
	}
	
	public GccTypeinfo getReferencedTypeinfo() {
		return (GccTypeinfo) typeinfoRef.getReferencedTypeinfo();
	}

	protected void setTypeinfoAddress()  {

		GccTypeinfo typeinfo = getReferencedTypeinfo();
		typeinfoAddress = typeinfo.getAddress();
		typeinfoNamespace = typeinfo.getNamespace();

	}

	public Address getTypeinfoAddress() {
		return typeinfoAddress;
	}

	protected void setTopOffsetValue() {

		try {
			Address topOffset = typeinfoRefAddress.subtract(defaultPointerSize);
			if (topOffset.getOffset() < vtableAddress.getOffset()) {
				Msg.debug(this,"No offset field in vtable at " + vtableAddress.toString());
				isValid = false;
				return;
			}

			topOffsetValue = extendedFlatAPI.getLongValueAt(topOffset);
		} catch (IllegalArgumentException e) {
			Msg.debug(this, "Invalid vtable: " + vtableAddress.toString() + " No offset field");
			isValid = false;
		}
	}

	private void setIsInternalVtable() {

		if (topOffsetValue == null) {
			isValid = false;
			return;
		}

		// if it has an existing label that is exactly "vtable" then set it true and
		// return
		Symbol primarySymbol = symbolTable.getPrimarySymbol(vtableAddress);
		if (primarySymbol != null && primarySymbol.getName().equals("vtable")) {
			isPrimary = true;
			return;

		}

		// otherwise, use the topOffsetValue to figure it out
		if (topOffsetValue == 0L) {
			isPrimary = true;
		} else {
			isPrimary = false;
		}
	}

	public Boolean isPrimary() {

		if (isPrimary == null) {
			isValid = false;
			return null;
		}

		return isPrimary;
	}

	public void setNumVfunctions(int num) {
		numVfunctions = num;
	}

	public Integer getNumVfunctions() {

		if (numVfunctions == null) {
			isValid = false;
			return null;
		}
		return numVfunctions;
	}

	protected void setHasVfunctions() throws CancelledException {

		Address typeinfoRefAddress = getTypeinfoRefAddress();
		if (isPrimary == null) {
			isValid = false;
			return;
		}

		try {
			Address possVfunctionTop = typeinfoRefAddress.add(defaultPointerSize);
			
			numVfunctions = getNumFunctionPointers(possVfunctionTop, true, false);
			if (numVfunctions == 0) {
				hasVfunctions = false;
			} else {
				hasVfunctions = true;
				vfunctionTop = possVfunctionTop;
			}
		} catch (AddressOutOfBoundsException e) {
			hasVfunctions = false;
		}

	}

	private int getNumFunctionPointers(Address topAddress, boolean allowNullFunctionPtrs,
			boolean allowDefaultRefsInMiddle) throws CancelledException {

		int numFunctionPointers = 0;
		Address address = topAddress;
		
		// if it has a primary non-default symbol and it isn't "vftable" then it isn't a vftable
		Symbol primarySymbol = symbolTable.getPrimarySymbol(topAddress);
		if(primarySymbol != null && primarySymbol.getSource() != SourceType.DEFAULT && !primarySymbol.getName().contains("vftable")) {
			return numFunctionPointers;
		}
		MemoryBlock currentBlock = program.getMemory().getBlock(topAddress);

		boolean stillInCurrentTable = true;
		while (address != null && currentBlock.contains(address) && stillInCurrentTable
				&& (isPossibleFunctionPointer(address) || (allowNullFunctionPtrs && isPossibleNullPointer(address)))) {

			numFunctionPointers++;
			address = address.add(defaultPointerSize);
			Symbol symbol = symbolTable.getPrimarySymbol(address);
			if (symbol == null) {
				continue;
			}
			// never let non-default refs in middle
			if (symbol.getSource() != SourceType.DEFAULT) {
				stillInCurrentTable = false;
			}

			// if it gets here it is default
			if (!allowDefaultRefsInMiddle) {
				stillInCurrentTable = false;
			}
		}
		
		//NEW: TESTING Don't allow single null pointer at top of vftable
		//OR test to see if nulls then typeinfo ptr
//		if(isPossibleNullPointer(topAddress) && numFunctionPointers == 1) {
//				return 0;
//		}
		
		// check to see if last is null ptr and next addr after that is typeinfo ref - indicating the null is really top of next vtable
		Address lastAddress = topAddress.add((numFunctionPointers-1)*defaultPointerSize);
		if(isPossibleNullPointer(lastAddress) && (isTypeinfoRef(lastAddress.add(defaultPointerSize)))){
			numFunctionPointers--;
		}
		return numFunctionPointers;
	}
	
	private boolean isTypeinfoRef(Address addr) {
		
		Address referencedAddress = getReferencedAddress(addr);
		if(referencedAddress == null) {
			return false;
		}
		Data data = program.getListing().getDataAt(referencedAddress);
		if(data == null) {
			return false;
		}
		
		if(data.getBaseDataType().getName().contains("ClassTypeInfoStructure")) {
			return true;
		}
		return false;
	}

	/**
	 * Method to determine if there are enough zeros to make a null poihnter and no
	 * references into or out of the middle
	 * 
	 * @param address the given address
	 * @return true if the given address could be a valid null pointer, false if not
	 */
	private boolean isPossibleNullPointer(Address address) throws CancelledException {
		if (!extendedFlatAPI.hasNumZeros(address, defaultPointerSize)) {
			return false;
		}
		return true;
	}

	/**
	 * Method to determine if the given address contains a possible function pointer
	 * 
	 * @param address the given address
	 * @return true if the given address contains a possible function pointer or
	 *         false otherwise
	 * @throws CancelledException if cancelled
	 */
	private boolean isPossibleFunctionPointer(Address address) throws CancelledException {

		// TODO: make one that works for all casea in helper
		// TODO: make sure it recognizes the external functions

		long longValue = extendedFlatAPI.getLongValueAt(address);

		Register lowBitCodeMode = program.getRegister("LowBitCodeMode");
		if (lowBitCodeMode != null) {
			longValue = longValue & ~0x1;
		}

		Address possibleFunctionPointer = null;

		try {
			possibleFunctionPointer = address.getNewAddress(longValue);
		} catch (AddressOutOfBoundsException e) {
			return false;
		}

		if (possibleFunctionPointer == null) {
			return false;
		}

		Function function = extendedFlatAPI.getFunctionAt(possibleFunctionPointer);
		if (function != null) {
			return true;
		}

		AddressSetView executeSet = program.getMemory().getExecuteSet();

		if (!executeSet.contains(possibleFunctionPointer)) {
			return false;
		}

		Instruction instruction = extendedFlatAPI.getInstructionAt(possibleFunctionPointer);
		if (instruction != null) {
			extendedFlatAPI.createFunction(possibleFunctionPointer, null);
			return true;

		}

		boolean disassemble = extendedFlatAPI.disassemble(possibleFunctionPointer);
		if (disassemble) {

			// check for the case where there is conflicting data at the thumb offset
			// function
			// pointer and if so clear the data and redisassemble and remove the bad
			// bookmark
			long originalLongValue = extendedFlatAPI.getLongValueAt(address);
			if (originalLongValue != longValue) {
				Address offsetPointer = address.getNewAddress(originalLongValue);
				if (extendedFlatAPI.getDataAt(offsetPointer) != null) {
					extendedFlatAPI.clearListing(offsetPointer);
					disassemble = extendedFlatAPI.disassemble(address);

					Bookmark bookmark = getBookmarkAt(possibleFunctionPointer, BookmarkType.ERROR, "Bad Instruction",
							"conflicting data");
					if (bookmark != null) {
						extendedFlatAPI.removeBookmark(bookmark);
					}
				}
			}

			extendedFlatAPI.createFunction(possibleFunctionPointer, null);
			return true;
		}
		return false;
	}

	private Bookmark getBookmarkAt(Address address, String bookmarkType, String category, String commentContains)
			throws CancelledException {

		Bookmark[] bookmarks = program.getBookmarkManager().getBookmarks(address);

		for (Bookmark bookmark : bookmarks) {
			monitor.checkCancelled();

			if (bookmark.getType().getTypeString().equals(bookmarkType) && bookmark.getCategory().equals(category)
					&& bookmark.getComment().contains(commentContains)) {
				return bookmark;
			}
		}
		return null;
	}

	public void setHasVfunctions(boolean flag) {
		hasVfunctions = flag;
	}

	public boolean hasVfunctions() {
		return hasVfunctions;
	}

	public Address getVfunctionTop() {
		return vfunctionTop;
	}

	protected void setLength() {

		if (hasVfunctions == null) {
			isValid = false;
			return;
		}
		if (!hasVfunctions) {
			length = (int) (typeinfoRefAddress.getOffset() + defaultPointerSize - vtableAddress.getOffset());
			return;
		}

		if (numVfunctions == null || vfunctionTop == null) {
			isValid = false;
			return;
		}

		Address endAddr = vfunctionTop.add(numVfunctions * defaultPointerSize);
		length = (int) (endAddr.getOffset() - vtableAddress.getOffset());

	}

	private void addToLength(int amountToAdd) {
		length = length + amountToAdd;
	}

	public int getLength() {
		return length;
	}

	private void findInternalVtables() throws CancelledException {

		// if the current table is already an internal vtable there won't be any
		// internal ones in it
		if (!isPrimary) {
			return;
		}

		boolean keepChecking = true;
		
		int limit = length;

		while (keepChecking) {

			monitor.checkCancelled();

			Address nextAddr = vtableAddress.add(length);
			
			
			Address typeinfoAddr = typeinfo.getAddress();
			
			int alignment = nextAddr.getSize()/8;
			Address nextTypeinfoRefAddr = getNextReferenceTo(nextAddr, typeinfoAddr, alignment, limit);
			if(nextTypeinfoRefAddr == null) {
				keepChecking = false;
				continue;
			}
			
			GccTypeinfoRef internalTypenfoRef = new GccTypeinfoRef(nextTypeinfoRefAddr, typeinfo, true);

			Vtable possibleInternalVtable = new Vtable(program, nextAddr,internalTypenfoRef, isSpecial, inExternalMemory,
					this, isConstruction, monitor);
			if (!possibleInternalVtable.isValid()) {
				keepChecking = false;
				continue;
			}

			if (possibleInternalVtable.isPrimary()) {
				keepChecking = false;
				continue;
			}

			Namespace internalVtableNamespace = possibleInternalVtable.getNamespace();
			if (internalVtableNamespace != null && internalVtableNamespace.equals(classNamespace)) {
				addInternalVtable(possibleInternalVtable);
			} else {
				keepChecking = false;
			}

		}
	}
	
	private Address getNextReferenceTo(Address startAddress, Address refdAddress, int alignment, int limit) {
		
		int offset = alignment;
		while(offset < limit) {
			Address addr = startAddress.add(offset);
			Address referencedAddress = getReferencedAddress(addr);
			if(referencedAddress != null && referencedAddress.equals(refdAddress)) {
				return addr;
			}
			offset += alignment;
		}
		return null;
	}

	private void addInternalVtable(Vtable internalVtable) {
		internalVtables.add(internalVtable);
		addToLength(internalVtable.getLength());
	}

	public List<Vtable> getInternalVtables() {
		return internalVtables;
	}

	
	// TODO: put in helper or ext api
	private boolean inExternalBlock(Address address) {

		MemoryBlock externalBlock = getExternalBlock();
		if (externalBlock == null) {
			return false;
		}
		if (externalBlock.contains(address)) {
			return true;
		}
		return false;

	}

	private MemoryBlock getExternalBlock() {
		return program.getMemory().getBlock("EXTERNAL");
	}

	
	public void setIsConstructionVtable(Boolean setting) {
		isConstruction = setting;
	}

	public Boolean isConstructionVtable() {
		return isConstruction;
	}

	private void figureOutNamespace() {
		
		if(isConstruction == null) {
			setNamespace(globalNamespace);
			return;
		}

		// if construction vtable can't figure out from within vtable object
		// have to assign later after further inspection of vtts and other info
		if (isConstruction != null && isConstructionVtable()) {
			setNamespace(globalNamespace);
			return;
		}

		if (isPrimary()) {
			setNamespace(typeinfoNamespace);
			return;
		}

		// if not primary and the primary has same namespace then it is an internal
		// vtable and can
		// set the namespace to the typeinfo namespace
		if (!primaryVtable.getNamespace().isGlobal() && primaryVtable.getNamespace().equals(typeinfoNamespace)) {
			setNamespace(typeinfoNamespace);
			return;
		}

	}

	// for setting namespaces after vtable is created when they can't
	// be determined by looking at internals of current vtable
	public void setNamespace(Namespace namespace) {

		classNamespace = namespace;
		for(Vtable internalVtable : internalVtables) {
			internalVtable.setNamespace(namespace);
		}
	}

	public Namespace getNamespace() {
		return classNamespace;
	}

	protected boolean applyVtableData() throws CancelledException, Exception {
		
		Data dataAt = listing.getDataAt(vtableAddress);

		// first check to see it is an erroneous vtable that has been made a byte array
		// if so, clear it and start looking for the typeinfo reference
		//TODO: check !isDefined and use known length to clear
		if (dataAt != null && dataAt.isArray()) {
			listing.clearCodeUnits(vtableAddress, vtableAddress, false);
		}

		if (dataAt != null && !dataAt.getDataType().getName().equals("long")) {
			listing.clearCodeUnits(vtableAddress, vtableAddress, false);
		}

		// create the typeinfo pointer if there isn't already one
		Data typeinfoPtr = listing.getDataAt(typeinfoRefAddress);
		if (typeinfoPtr == null || !typeinfoPtr.isDefined()) {
			DataType nullPointer = dataTypeManager.getPointer(null);

			listing.createData(typeinfoRefAddress, nullPointer);

		}

		// create longs from top of vtable to the typeinfo reference
		createLongs(this.vtableAddress, typeinfoRefAddress);

		int numFunctionPointers = getNumVfunctions();

		if (numFunctionPointers != 0) {

			Address vftableAddress = getVfunctionTop();

			createVftableArray(vftableAddress, numFunctionPointers);
		}

		return true;
	}

	public Data createVftableArray(Address vftableAddress, int numFunctionPointers)
			throws CancelledException, AddressOutOfBoundsException {

		listing.clearCodeUnits(vftableAddress,
				vftableAddress.add((numFunctionPointers * defaultPointerSize - 1)), false);

		DataType pointerDataType = dataTypeManager.getPointer(null);
		ArrayDataType vftableArrayDataType = new ArrayDataType(pointerDataType, numFunctionPointers,
				defaultPointerSize);
		try {
			Data vftableArrayData = listing.createData(vftableAddress, vftableArrayDataType);
			return vftableArrayData;
		} catch (Exception e) {
			return null;
		}

	}

	/**
	 * Method to create a series of long data types from the given start address to
	 * the given end address
	 * 
	 * @param start the starting address
	 * @param end   the ending address
	 * @throws CancelledException if cancelled
	 * @throws Exception          if data has conflict when created
	 */
	private void createLongs(Address start, Address end) throws CancelledException, Exception {

		DataType longDT = new LongDataType(dataTypeManager);
		if (defaultPointerSize == 8) {	
			longDT = new LongLongDataType();
		}
		int offset = 0;
		Address address = start;
		while (address != null && !address.equals(end)) {

			listing.clearCodeUnits(address, address.add(defaultPointerSize - 1),false);
			listing.createData(address, longDT);
			offset += defaultPointerSize;
			address = getAddress(start, offset);
		}

	}
	
	/**
	 * Method to get address at address + offset
	 * 
	 * @param address the given address
	 * @param offset  the given offset
	 * @return the address at address + offset or null if it doesn't exist
	 */
	private Address getAddress(Address address, int offset) {
		try {
			Address newAddress = address.add(offset);
			return newAddress;
		} catch (AddressOutOfBoundsException e) {
			return null;
		}
	}
	
	private Address getReferencedAddress(Address address) {
		
		int addressSize = address.getSize();
		Memory memory = program.getMemory();
		try {
			
			if (addressSize == 32) {
				long offset32 = memory.getInt(address);
				Address newAddr = address.getNewAddress(offset32);
				if(memory.contains(newAddr)) {
					return newAddr;
				}
				return null;

			}
			else if (addressSize == 64) {

				long offset64 = memory.getLong(address);
				Address newAddr = address.getNewAddress(offset64);
				if(memory.contains(newAddr)) {
					return newAddr;
				}
				return null;

			}
			else {
				return null;
			}
		}
		catch (MemoryAccessException e) {
			return null;
		}
	}

}
