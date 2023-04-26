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
//DO NOT RUN. THIS IS NOT A SCRIPT! THIS IS A CLASS THAT IS USED BY SCRIPTS. 
package classrecovery;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.analysis.ReferenceAddressPair;
import ghidra.app.util.PseudoDisassembler;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.IsolatedEntrySubModel;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IBO32DataType;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.data.Undefined8DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ExtendedFlatProgramAPI extends FlatProgramAPI {

	final int defaultPointerSize;

	public ExtendedFlatProgramAPI(Program program, TaskMonitor taskMonitor) {

		super(program, taskMonitor);
		defaultPointerSize = program.getDefaultPointerSize();
	}

	// Return true if the passed data is an array or structure of pointers.
	// Return false otherwise. 
	public boolean isArrayOrStructureOfAllPointers(Data data)
			throws CancelledException {

		if (data == null) {
			return false;
		}

		if (!data.isArray() && !data.isStructure()) {
			return false;
		}

		int numComponents = data.getNumComponents();

		for (int ii = 0; ii < numComponents; ++ii) {
			monitor.checkCancelled();

			Data component = data.getComponent(ii);
			if (!component.isPointer()) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Method to get the pointer formed by the bytes at the current address
	 * @param address the given address
	 * @return the pointer formed by the bytes at the current address
	 */
	public Address getPointer(Address address) {

		try {
			long offset = 0;

			if (defaultPointerSize == 4) {
				offset = getInt(address);
			}
			if (defaultPointerSize == 8) {
				offset = getLong(address);
			}
			if (offset == 0) {
				return null;
			}

			Address possiblePointer = address.getNewAddress(offset);
			return possiblePointer;

		}
		catch (MemoryAccessException e) {
			return null;
		}
		catch (AddressOutOfBoundsException e) {
			return null;
		}
	}

	/**
	 * Method to check to see if there is a valid function pointer at the given address. If it is 
	 * valid but not created, create it
	 * @param address the given address
	 * @param allowNullFunctionPointer if true, allow null pointers as a valid function pointer
	 * @return true if it is a functin pointer, else returns false
	 * @throws CancelledException if cancelled
	 */
	public boolean isFunctionPointer(Address address, boolean allowNullFunctionPointer)
			throws CancelledException {

		// check for or create null pointer if valid number of zeros at address
		if (isNullPointer(address) && allowNullFunctionPointer) {
			return true;
		}

		// check for or create function pointer if valid function pointed to
		Data data = currentProgram.getListing().getDefinedDataAt(address);
		if (data != null) {
			if (data.isPointer() && getReferencedFunction(address) != null) {
				return true;
			}
		}
		else {

			PointerDataType pointerDataType = new PointerDataType();

			try {
				data = createData(address, pointerDataType);
				if (getReferencedFunction(address) != null) {
					return true;
				}
				clearListing(address);
				return false;
			}
			catch (CancelledException e) {
				throw e;
			}
			catch (Exception e) {
				return false;
			}
		}
		return false;

	}

	/**
	 * Method to determine if the given address is a null pointer. If it isn't but is valid length
	 * of zeros, try creating one. 
	 * @param address the given address
	 * @return true if given address is a valid null pointer, false otherwise
	 * @throws CancelledException if cancelled
	 */
	public boolean isNullPointer(Address address) throws CancelledException {

		if (!hasNumZeros(address, defaultPointerSize)) {
			return false;
		}

		DataType nullPointer = currentProgram.getDataTypeManager().getPointer(null);
		Listing listing = currentProgram.getListing();
		Data d = listing.getDefinedDataAt(address);
		if (d == null) {
			try {
				d = createData(address, nullPointer);
			}
			catch (Exception e) {
				return false;
			}

		}

		PointerDataType pointerDataType = new PointerDataType();
		if (d.getDataType().isEquivalent(pointerDataType)) {
			return true;
		}

		return false;

	}

	/**
	 * Method to check for num zeros at the given address
	 * @param address the given address
	 * @param numZeros the number of zeros to check for
	 * @return true if there are numZero zeros at the given address
	 * @throws CancelledException if cancelled
	 */
	public boolean hasNumZeros(Address address, int numZeros) throws CancelledException {

		int index = 0;
		try {
			while (index < numZeros) {
				monitor.checkCancelled();
				if (getByte(address.add(index)) != 0x00) {
					return false;
				}
				index++;
			}
		}
		catch (MemoryAccessException e) {
			return false;
		}
		catch (AddressOutOfBoundsException e) {
			return false;
		}
		return true;
	}

	/**
	 * Method to get the function referenced at the given address if there is one. If the function
	 * is a thunk, get the thunked function
	 * @param address the given address
	 * @return the (thunked if a thunk) function pointed to by the given address
	 */
	public Function getReferencedFunction(Address address) {

		List<Address> referencesFrom = getReferenceFromAddresses(address);
		if (referencesFrom.size() != 1) {
			return null;
		}
		
		

		Address functionAddress = referencesFrom.get(0);
		
		Register lowBitCodeMode = currentProgram.getRegister("LowBitCodeMode");
		if(lowBitCodeMode != null) {
			long longValue = functionAddress.getOffset();
			longValue = longValue & ~0x1;
			functionAddress = functionAddress.getNewAddress(longValue);
		}
		
		Function function = getFunctionAt(functionAddress);
		if (function == null) {
			// try to create function
			function = createFunction(functionAddress, null);
			if (function == null) {
				return null;
			}
		}

		//if function is a thunk, get the thunked function					
		if (function.isThunk()) {
			Function thunkedFunction = function.getThunkedFunction(true);
			function = thunkedFunction;
		}
		return function;
	}

	/**
	 * Method to get a list of addresses that are the "reference froms" of the given address
	 * @param address the given address
	 * @return a list of addresses that are references from the given address
	 */
	public List<Address> getReferenceFromAddresses(Address address) {

		Reference[] referencesFrom = getReferencesFrom(address);

		// get only the address references at the given address (ie no stack refs, ...)
		List<Address> refFromAddresses = new ArrayList<Address>();
		for (Reference referenceFrom : referencesFrom) {
			if (referenceFrom.isMemoryReference()) {
				refFromAddresses.add(referenceFrom.getToAddress());
			}
		}

		return refFromAddresses;
	}

	/**
	 * Method to get address at address + offset
	 * @param address the given address
	 * @param offset the given offset
	 * @return the address at address + offset or null if it doesn't exist
	 */
	public Address getAddress(Address address, int offset) {
		try {
			Address newAddress = address.add(offset);
			return newAddress;
		}
		catch (AddressOutOfBoundsException e) {
			return null;
		}
	}

	/**
	 * Method to create the first function after the last terminating function before the given 
	 * address which is in the middle of undefined bytes
	 * @param address the given address
	 * @param expectedFiller the expected filler byte value
	 * @return the created function or null if not created
	 */
	public Function createFunctionBefore(Address address, Byte expectedFiller) {

		PseudoDisassembler pseudoDisassembler = new PseudoDisassembler(currentProgram);

		// skip any undefineds and get the defined instruction before the given address
		Instruction instructionBefore = getInstructionBefore(address);

		if (instructionBefore == null) {
			return null;
		}

		Address instBeforeAddr = instructionBefore.getAddress();

		Memory memory = currentProgram.getMemory();
		if (!memory.getBlock(address).equals(memory.getBlock(instBeforeAddr))) {
			return null;
		}

		// set some arbritrary limit on how far back to go
		if (address.subtract(instBeforeAddr) > 2000) {
			return null;
		}

		// if the instruction before all the undefines bytes doesn't indicate that it is the end 
		// of a function or an end of a range of a function then return
		FlowType flowType = instructionBefore.getFlowType();
		if (!flowType.isTerminal() && !flowType.isJump()) {
			return null;
		}

		//get the last address in the instruction
		Address maxAddress = instructionBefore.getMaxAddress();
		int maxLen = (int) (address.getOffset() - maxAddress.getOffset());
		if (maxLen <= 0) {
			return null;
		}

		int offset = 1;

		// skip the filler
		Byte filler;
		try {
			filler = getByte(maxAddress.add(offset));
			while (expectedFiller.equals(filler) && offset <= maxLen) {
				offset++;
				filler = getByte(maxAddress.add(offset));
			}
		}
		catch (MemoryAccessException e) {
			return null;
		}
		catch (AddressOutOfBoundsException e) {
			return null;
		}

		Address functionStart = maxAddress.add(offset);

		// check to see if the address after the instruction and filler is the start of a valid 
		// subroutine
		if (!pseudoDisassembler.isValidSubroutine(functionStart, true)) {
			return null;
		}
		if (getInstructionAt(functionStart) == null) {
			disassemble(functionStart);
		}

		// if so, create a function there
		Function function = createFunction(functionStart, null);

		return function;
	}

	public Byte determineFillerByte() throws CancelledException, MemoryAccessException {

		Byte filler = null;
		int functionsToCheck = 30;
		Address minAddress = currentProgram.getMinAddress();
		Function currentFunction = getFunctionAfter(minAddress);

		while (currentFunction != null && functionsToCheck != 0) {
			monitor.checkCancelled();
			Address maxAddress = currentFunction.getBody().getMaxAddress();
			Address fillerAddress = getAddress(maxAddress, 1);

			// if no next address or next function is directly after current then skip
			if (fillerAddress == null || getFunctionContaining(fillerAddress) != null) {
				currentFunction = getFunctionAfter(maxAddress);
				continue;
			}

			// get the number of same byte fillers after current function
			int numFiller = getNumberOfSameFillerBytesStartingAtAddress(fillerAddress);
			if (numFiller == 0) {
				currentFunction = getFunctionAfter(maxAddress);
				continue;
			}

			// if there is filler but the next function isn't directly after the filler then skip
			if (numFiller > 0) {
				functionsToCheck--;
				Address addressAfterLastFiller = getAddress(fillerAddress, numFiller);
				if (addressAfterLastFiller == null ||
					getFunctionAt(addressAfterLastFiller) == null) {
					currentFunction = getFunctionAfter(maxAddress);
					continue;
				}
				// if same filler value fills in all addresses between two functions then get the
				// filler value 
				Byte currentFiller = getByte(fillerAddress);
				if (filler == null) {
					filler = currentFiller;
					currentFunction = getFunctionAfter(maxAddress);
					continue;
				}
				if (!filler.equals(currentFiller)) {
					return null;
				}
			}
		}
		// get number of undefined bytes
		// get address of end of undefineds and make sure it is a function
		// if so, see if all bytes are same
		// make the second function the new current function

		return filler;
	}

	public int getNumberOfSameFillerBytesStartingAtAddress(Address firstAddress)
			throws CancelledException, MemoryAccessException {

		AddressSetView validMemory = currentProgram.getMemory().getLoadedAndInitializedAddressSet();

		if (firstAddress == null) {
			return 0;
		}
		Address address = firstAddress;
		int numSameByte = 0;
		byte currentByte = getByte(address);
		while (validMemory.contains(address) && getFunctionContaining(address) == null) {
			monitor.checkCancelled();
			numSameByte++;
			address = getAddress(firstAddress, numSameByte);
			if (address == null) {
				return numSameByte;
			}
			byte nextByte = getByte(address);
			if (nextByte != currentByte) {
				return numSameByte;
			}
		}

		return numSameByte;
	}

	/**
	 * Method to create functions given the list of addresses known to be contained in a function but
	 * that are not yet created
	 * @param containedAddresses list of address contained in an undefined function
	 * @throws CancelledException, MemoryAccessException 
	 * @throws MemoryAccessException if issue accessing memory
	 */
	public void createUndefinedFunctions(List<Address> containedAddresses)
			throws CancelledException, MemoryAccessException {

		Byte filler = determineFillerByte();
		if (filler == null) {
			return;
		}

		Iterator<Address> iterator = containedAddresses.iterator();
		while (iterator.hasNext()) {
			monitor.checkCancelled();
			Address address = iterator.next();

			// a previously created one might call the one that contains this so
			// it may have already been created - if so, skip
			Function functionContaining = getFunctionContaining(address);
			if (functionContaining != null) {
				continue;
			}

			Function newFunction = createFunctionBefore(address, filler);
			if (newFunction == null) {
				continue;
			}

			AddressSetView functionBody = newFunction.getBody();
			while (!functionBody.contains(address)) {
				newFunction = createFunctionBefore(address, filler);
				if (newFunction == null) {
					continue;
				}
				functionBody = newFunction.getBody();
			}
		}
	}

	/**
	 * Method to create a function in the given program at the given address
	 * @param prog the given program
	 * @param addr the given address
	 * @return true if the function was created, false otherwise
	 */
	public boolean createFunction(Program prog, Address addr) {

		try {
			AddressSet subroutineAddresses = getSubroutineAddresses(prog, addr);
			if (subroutineAddresses.isEmpty()) {
				return false;
			}

			CreateFunctionCmd cmd = new CreateFunctionCmd(null, subroutineAddresses.getMinAddress(),
				null, SourceType.DEFAULT);
			if (cmd.applyTo(prog, monitor)) {
				return true;
			}

			return false;
		}
		catch (CancelledException e) {
			// FIXME: this should not be caught by this method and should propogate 
			return false;
		}

	}

	/**
	 * Method to figure out a subroutine address set given an address contained in it
	 * @param program the given program
	 * @param address address in the potential subroutine
	 * @return address set of the subroutine to be created
	 * @throws CancelledException if cancelled
	 */
	public AddressSet getSubroutineAddresses(Program program, Address address)
			throws CancelledException {

		// FIXME: Should not be passing program arg

		// Create a new address set to hold the entire selection.
		AddressSet subroutineAddresses = new AddressSet();

		IsolatedEntrySubModel model = new IsolatedEntrySubModel(currentProgram);
		CodeBlock[] codeBlocksContaining = model.getCodeBlocksContaining(address, monitor);

		for (CodeBlock element : codeBlocksContaining) {

			if (monitor.isCancelled()) {
				return subroutineAddresses;
			}
			subroutineAddresses.add(element);
		}

		return subroutineAddresses;
	}


	/**
	 * Method to get a list of symbols either matching exactly (if exact flag is true) or containing (if exact flag is false) the given symbol name
	 * @param addressSet the address set to find matching symbols in
	 * @param symbolName the symbol name to match
	 * @param exact flag used to determine whether to return only exact symbol name matches or ones that contain the given symbol
	 * @return list of symbols in the address set with the given symbol name, only exact ones if exact flag is true or ones that contain the symbol if exact is false
	 * @throws CancelledException if cancelled
	 */
	public List<Symbol> getListOfSymbolsInAddressSet(AddressSet addressSet, String symbolName,
			boolean exact) throws CancelledException {

		List<Symbol> symbolsInSet = new ArrayList<Symbol>();

		SymbolIterator symbols =
			currentProgram.getSymbolTable().getSymbols(addressSet, SymbolType.LABEL, true);

		while (symbols.hasNext()) {
			monitor.checkCancelled();
			Symbol symbol = symbols.next();
			if (exact && symbol.getName().equals(symbolName)) {
				symbolsInSet.add(symbol);
				continue;
			}
			if (!exact && symbol.getName().contains(symbolName)) {
				symbolsInSet.add(symbol);
			}
		}
		return symbolsInSet;
	}

	/**
	 * Method to return the referenced address at the given address
	 * Note: this will work whether there is a created reference or not
	 * @param address the address to look for a referenced address at
	 * @param getIboIf64bit if true, get the address corresponding to the image base offset instead 
	 * of the full reference address
	 * @return the first referenced address from the given address
	 */
	public Address getReferencedAddress(Address address, boolean getIboIf64bit) {

		int addressSize = address.getSize();
		if (addressSize == 64 && getIboIf64bit) {
			IBO32DataType ibo32 =
				new IBO32DataType(currentProgram.getDataTypeManager());
			int length = ibo32.getLength();
			DumbMemBufferImpl compMemBuffer =
				new DumbMemBufferImpl(currentProgram.getMemory(), address);
			Object value = ibo32.getValue(compMemBuffer, ibo32.getDefaultSettings(), length);
			if (value instanceof Address) {
				Address iboAddress = (Address) value;
				return iboAddress;
			}
			return null;
		}

		try {
			if (addressSize == 32) {
				long offset32 = getInt(address);
				Address newAddr = address.getNewAddress(offset32);
				if(currentProgram.getMemory().contains(newAddr)) {
					return newAddr;
				}
				return null;

			}
			else if (addressSize == 64) {

				long offset64 = getLong(address);
				Address newAddr = address.getNewAddress(offset64);
				if(currentProgram.getMemory().contains(newAddr)) {
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
	
	public long getLongValueAt(Address address) {
		
		MemBuffer buf = new DumbMemBufferImpl(currentProgram.getMemory(), address);
		
		LongDataType longDT = new LongDataType();

		Scalar value =
			(Scalar) longDT.getValue(buf, longDT.getDefaultSettings(), defaultPointerSize);

		return value.getSignedValue();
	}

	/**
	 * Method to return a list of symbols with the given name and namespace. 
	 * @param symbolName the symbol name to retrieve
	 * @param namespace the namespace to look for symbols with the given name
	 * @param exact if true, return only exact symbol names, if false, return symbols that contain the given n name
	 * @return List of symbols in given namespace either with exact matching name or containing name
	 * @throws CancelledException when cancelled
	 */
	public List<Symbol> getListOfSymbolsByNameInNamespace(String symbolName, Namespace namespace,
			boolean exact) throws CancelledException {

		List<Symbol> symbolList = new ArrayList<Symbol>();

		// FIXME: if you are going to pass namespace arg you should use its program not currentProgram
		SymbolIterator symbols = currentProgram.getSymbolTable().getSymbols(namespace);

		while (symbols.hasNext()) {
			monitor.checkCancelled();
			Symbol symbol = symbols.next();
			if (exact && symbol.getName().equals(symbolName)) {
				symbolList.add(symbol);
				continue;
			}
			if (!exact && symbol.getName().contains(symbolName)) {
				symbolList.add(symbol);
			}
		}
		return symbolList;
	}

	public boolean doesFunctionACallAnyListedFunction(Function aFunction, List<Function> bFunctions)
			throws CancelledException {

		if (aFunction == null) {
			return false;
		}

		Iterator<Function> bFunctionsIterator = bFunctions.iterator();
		while (bFunctionsIterator.hasNext()) {
			monitor.checkCancelled();
			Function bFunction = bFunctionsIterator.next();
			if (doesFunctionACallFunctionB(aFunction, bFunction)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Get the nth called function from calling function
	 * @param callingFunction The calling function
	 * @param callIndex the called function index (ie 1 = first called function)
	 * @param getThunkedFunction if true get the thunked function, if false get the thunk itself, if
	 * there is a thunk
	 * @return the nth called function in calling function
	 * @throws CancelledException if cancelled
	 */
	public Function getCalledFunctionByCallOrder(Function callingFunction, int callIndex,
			boolean getThunkedFunction) throws CancelledException {

		int callNumber = 0;
		InstructionIterator instructions = callingFunction.getProgram()
				.getListing()
				.getInstructions(callingFunction.getBody(), true);
		while (instructions.hasNext() && callNumber < callIndex) {
			monitor.checkCancelled();
			Instruction instruction = instructions.next();
			if (instruction.getFlowType().isCall()) {
				callNumber++;
				if (callNumber == callIndex) {
					Function referencedFunction =
						getReferencedFunction(instruction.getMinAddress(), getThunkedFunction);
					return referencedFunction;
				}
			}
		}
		return null;
	}

	/**
	 * Method to retrieve an ordered list (ordered by reference address low to high) of 
	 * ReferenceAddressPairs of called functions given the calling function
	 * @param callingFunction the calling function
	 * @return an ordered list (ordered by reference address low to high) of ReferenceAddressPairs 
	 * of called functions given the calling function
	 * @throws CancelledException if cancelled
	 */
	public List<ReferenceAddressPair> getOrderedReferenceAddressPairsFromCallingFunction(
			Function callingFunction) throws CancelledException {

		List<ReferenceAddressPair> referenceAddressPairs = new ArrayList<ReferenceAddressPair>();

		Iterator<Function> calledFunctionsIterator =
			callingFunction.getCalledFunctions(monitor).iterator();
		while (calledFunctionsIterator.hasNext()) {
			monitor.checkCancelled();
			Function calledFunction = calledFunctionsIterator.next();
			List<Address> referencesToFunctionBFromFunctionA =
				getReferencesToFunctionBFromFunctionA(callingFunction, calledFunction);
			// add them to list of ref address pairs
			Iterator<Address> iterator = referencesToFunctionBFromFunctionA.iterator();
			while (iterator.hasNext()) {
				monitor.checkCancelled();
				Address sourceRefAddr = iterator.next();
				referenceAddressPairs.add(
					new ReferenceAddressPair(sourceRefAddr, calledFunction.getEntryPoint()));
			}
		}

		referenceAddressPairs.sort((a1, a2) -> a1.getSource().compareTo(a2.getSource()));
		return referenceAddressPairs;
	}

	/**
	 * Method to get reference addresses to function b from function a
	 * @param aFunction function a
	 * @param bFunction function b
	 * @return a list of reference address to function b from function a
	 * @throws CancelledException if cancelled
	 */
	public List<Address> getReferencesToFunctionBFromFunctionA(Function aFunction,
			Function bFunction) throws CancelledException {

		List<Address> referenceAddresses = new ArrayList<Address>();

		// FIXME: if you pass a function arg you should use its program, not currentProgram
		ReferenceIterator referencesToFunctionBIterator =
			currentProgram.getReferenceManager().getReferencesTo(bFunction.getEntryPoint());

		while (referencesToFunctionBIterator.hasNext()) {

			monitor.checkCancelled();
			Reference ref = referencesToFunctionBIterator.next();

			if (aFunction.getBody().contains(ref.getFromAddress())) {
				referenceAddresses.add(ref.getFromAddress());
			}
		}
		return referenceAddresses;
	}

	/**
	 * Method to determine if function a calls function b (or its thunk)
	 * @param aFunction function a
	 * @param bFunction function b
	 * @return true if function a calls function b (or its thunk), false otherwise
	 * @throws CancelledException if cancelled
	 */
	public boolean doesFunctionACallFunctionB(Function aFunction, Function bFunction)
			throws CancelledException {

		if (aFunction == null) {
			return false;
		}

		if (bFunction == null) {
			return false;
		}

		Set<Function> calledFunctions = aFunction.getCalledFunctions(monitor);
		if (calledFunctions.contains(bFunction)) {
			return true;
		}
		Iterator<Function> functionIterator = calledFunctions.iterator();
		while (functionIterator.hasNext()) {
			monitor.checkCancelled();
			Function calledFunction = functionIterator.next();
			if (calledFunction.isThunk()) {
				calledFunction = calledFunction.getThunkedFunction(true);
				if (calledFunction.equals(bFunction)) {
					return true;
				}
			}
		}
		return false;
	}


	/**
	 * Method to retrieve a single referenced address from the given address
	 * @param address the given address to look for a single referenced address
	 * @return the address referred to or null if none or more than one referenced
	 */
	public Address getSingleReferencedAddress(Address address) {

		List<Address> refFromAddresses = getReferenceFromAddresses(address);

		if (refFromAddresses.size() != 1) {
			return null;
		}

		return refFromAddresses.get(0);
	}

	/**
	 * Method to check for pointer to empty structure data type
	 * @param dataType the DataType to check
	 * @return true if empty, false if not empty
	 */
	public boolean isPointerToEmptyStructure(DataType dataType) {
		if (dataType instanceof Pointer) {
			Pointer ptr = (Pointer) dataType;
			DataType baseDataType = ptr.getDataType();
			if (baseDataType instanceof Structure && baseDataType.isNotYetDefined()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Method to create a PointerDataType to an appropriately sized undefined data type or
	 * a generic pointer data type
	 * @param dataType DataType
	 * @return PointerDataType to appropriately sized undefined data type
	 */
	public PointerDataType createPointerToUndefinedDataType(DataType dataType) {

		PointerDataType pdt = new PointerDataType();
		int dtLen = dataType.getLength();
		if (dataType instanceof Pointer) {
			if (dtLen == 4) {
				pdt = new PointerDataType(new Undefined4DataType());
			}
			if (dtLen == 8) {
				pdt = new PointerDataType(new Undefined8DataType());
			}
		}
		return pdt;
	}

	/**
	 * Method to retrieve the referenced Functions from the given referenceToClassMap
	 * @param referenceToClassMap map of addresses that contain a reference to either a vftable or 
	 * called function for a particular function
	 * @return List of functions referenced in the map
	 * @throws CancelledException if cancelled
	 */
	public List<Address> getReferencesToFunctions(Map<Address, RecoveredClass> referenceToClassMap)
			throws CancelledException {

		List<Address> referencesToFunctions = new ArrayList<Address>();

		List<Address> referenceAddresses = new ArrayList<Address>(referenceToClassMap.keySet());
		Iterator<Address> referenceIterator = referenceAddresses.iterator();
		while (referenceIterator.hasNext()) {
			monitor.checkCancelled();
			Address referenceAddress = referenceIterator.next();

			Function function = getReferencedFunction(referenceAddress, true);

			// skip the ones that reference a vftable
			if (function != null) {
				referencesToFunctions.add(referenceAddress);
			}
		}

		return referencesToFunctions;
	}

	/**
	 * Method to get the function referenced at the given address
	 * @param address the given address
	 * @param getThunkedFunction if true and referenced function is a thunk, get the thunked function
	 * @return the referenced function or null if no function is referenced
	 * @throws CancelledException if cancelled
	 */
	public Function getReferencedFunction(Address address, boolean getThunkedFunction)
			throws CancelledException {

		Reference[] referencesFrom = getReferencesFrom(address);

		if (referencesFrom.length == 0) {
			return null;
		}

		for (Reference referenceFrom : referencesFrom) {

			monitor.checkCancelled();

			Address referencedAddress = referenceFrom.getToAddress();
			if (referencedAddress == null) {
				continue;
			}

			Function function = getFunctionAt(referencedAddress);

			if (function == null) {
				continue;
			}

			if (!getThunkedFunction) {
				return function;
			}

			if (function.isThunk()) {
				function = function.getThunkedFunction(true);
			}
			return function;
		}

		return null;

	}

	/**
	 * Method to return the Structure data type that the given data type points to or null
	 * if given data type is not a pointer of if it doesn't point to a structure
	 * @param dataType the given data type
	 * @return  the base structure data type or null if the base data type isn't a structure
	 */
	public Structure getBaseStructureDataType(DataType dataType) {
		if (dataType instanceof Pointer) {
			Pointer ptr = (Pointer) dataType;
			DataType baseDataType = ptr.getDataType();
			if (baseDataType instanceof Structure) {
				return (Structure) baseDataType;
			}
			return null;
		}

		return null;
	}

	/**
	 * Method to check for pointer to empty structure data type
	 * @param dataType the DataType to check
	 * @return true if empty, false if not empty
	 */
	public boolean isEmptyStructure(DataType dataType) {

		if (dataType instanceof Structure && dataType.isNotYetDefined()) {
			return true;
		}

		return false;
	}

	/**
	 * Method to remove all symbols at the given address
	 * @param address the given address
	 * @throws CancelledException if cancelled
	 */
	public void removeAllSymbolsAtAddress(Address address) throws CancelledException {

		SymbolTable symbolTable = currentProgram.getSymbolTable();

		Symbol primarySymbol = symbolTable.getPrimarySymbol(address);

		while (primarySymbol != null && primarySymbol.getSource() != SourceType.DEFAULT) {
			monitor.checkCancelled();
			symbolTable.removeSymbolSpecial(primarySymbol);
			primarySymbol = symbolTable.getPrimarySymbol(address);
		}
	}

	/**
	 * Method to add the given string to a plate comment unless the string already exists in it. 
	 * @param address the given address
	 * @param comment the comment to add to the plate comment at the given address
	 */
	public void addUniqueStringToPlateComment(Address address, String comment) {

		String plateComment = getPlateComment(address);

		if (plateComment == null) {
			setPlateComment(address, comment);
			return;
		}

		if (!plateComment.contains(comment)) {
			setPlateComment(address, plateComment + "\r\n" + comment);
		}
	}

	/**
	 * Method to determine if there are any symbols in the given namespace
	 * @param namespace the given namespace
	 * @return true if there are any symbols in the given namespace, false otherwise
	 */
	public boolean hasSymbolsInNamespace(Namespace namespace) {

		// FIXME: if you are going to use a Namespace arg you should its program not currentProgram
		SymbolIterator namespaceSymbols = currentProgram.getSymbolTable().getSymbols(namespace);

		if (namespaceSymbols.hasNext()) {
			return true;
		}
		return false;

	}

	/**
	 * Create data type manager path combining the given parent category path and namespace
	 * @param parent the given parent CategoryPath
	 * @param namespace the given namespace
	 * @return CategoryPath for new categoryName 
	 * @throws CancelledException if cancelled
	 */
	public CategoryPath createDataTypeCategoryPath(CategoryPath parent, Namespace namespace)
			throws CancelledException {

		CategoryPath dataTypePath = parent;

		for (String name : namespace.getPathList(true)) {
			monitor.checkCancelled();

			dataTypePath = new CategoryPath(dataTypePath, name);
		}
		return dataTypePath;

	}

	/**
	 * Method to check the given string to see if it contains valid template(s)
	 * @param name the given name to check
	 * @return true if name contains valid template(s), false otherwise
	 */
	private boolean containsTemplate(String name) {

		if (!name.contains("<")) {
			return false;
		}

		int numOpenLips = getNumSubstrings(name, "<");
		int numClosedLips = getNumSubstrings(name, ">");

		if (numOpenLips > 0 && numClosedLips > 0 && numOpenLips == numClosedLips) {
			return true;
		}
		return false;
	}

	private boolean containsSimpleTemplate(String name) {

		int indexOf = name.indexOf(",");
		if (indexOf == -1) {
			return true;
		}
		return false;
	}

	/**
	 * Method to return the number of the given substrings contained in the given string
	 * @param string the given string
	 * @param substring the given substring
	 * @return the number of the given substrings in the given string
	 */
	private int getNumSubstrings(String string, String substring) {

		int num = 0;

		int indexOf = string.indexOf(substring);
		while (indexOf >= 0) {
			num++;
			string = string.substring(indexOf + 1);
			indexOf = string.indexOf(substring);
		}
		return num;
	}

	/**
	 * Method to generate unique shorted names for classes with templates
	 * @param recoveredClasses the list of classes in the program
	 * @throws CancelledException if cancelled
	 */
	public void createShortenedTemplateNamesForClasses(List<RecoveredClass> recoveredClasses)
			throws CancelledException {

		List<RecoveredClass> classesWithTemplates = new ArrayList<RecoveredClass>();

		// create list with only classes that have templates in name and add completely stripped
		// template name to class var
		Iterator<RecoveredClass> recoveredClassesIterator = recoveredClasses.iterator();
		while (recoveredClassesIterator.hasNext()) {
			monitor.checkCancelled();
			RecoveredClass recoveredClass = recoveredClassesIterator.next();

			String className = recoveredClass.getName();

			if (containsTemplate(className)) {
				String shortenedName = removeTemplate(className) + "<...>";
				recoveredClass.addShortenedTemplatedName(shortenedName);
				classesWithTemplates.add(recoveredClass);
			}
		}

		// iterate over map and remove entries that already have unique shortened names on map and 
		// add those unique names to class as shorted name
		// for those with non-unique names, process them as a group of matched names
		List<RecoveredClass> classesToProcess = new ArrayList<RecoveredClass>(classesWithTemplates);

		Iterator<RecoveredClass> classWithTemplatesIterator = classesWithTemplates.iterator();

		while (classWithTemplatesIterator.hasNext()) {
			monitor.checkCancelled();
			RecoveredClass currentClass = classWithTemplatesIterator.next();

			// skip if already processed
			if (!classesToProcess.contains(currentClass)) {
				continue;
			}

			String currentShortenedName = currentClass.getShortenedTemplateName();

			// if removing the middle of template results in unique name then keep that name and
			// remove class from list to process
			List<RecoveredClass> classesWithSameShortenedName =
				getClassesWithSameShortenedName(classesToProcess, currentShortenedName);

			if (classesWithSameShortenedName.size() == 1) {
				classesToProcess.remove(currentClass);
				continue;
			}

			Iterator<RecoveredClass> classesWithSameShortnameIterator =
				classesWithSameShortenedName.iterator();
			while (classesWithSameShortnameIterator.hasNext()) {
				monitor.checkCancelled();

				RecoveredClass classWithSameShortName = classesWithSameShortnameIterator.next();

				// if removing the middle of template results in duplicate names then
				// check for a simple internal to the template (ie just one item in it
				// if that is the case then just keep the original name 
				if (containsSimpleTemplate(classWithSameShortName.getName())) {
					classWithSameShortName.addShortenedTemplatedName(new String());
					classesWithSameShortnameIterator.remove();
					classesToProcess.remove(classWithSameShortName);
				}
			}

			// if none left after removing simple ones then continue processing next class
			if (classesWithSameShortenedName.isEmpty()) {
				continue;
			}

			// if only one left after removing the simple templates then use it with first part of 
			// template internal
			if (classesWithSameShortenedName.size() == 1) {
				RecoveredClass classWithSameShortName = classesWithSameShortenedName.get(0);
				String newName = getNewShortenedTemplateName(classWithSameShortName, 1);
				classWithSameShortName.addShortenedTemplatedName(newName);
				classesToProcess.remove(classWithSameShortName);
				continue;
			}

			// if more than one complex left over after all the removals above, then keep trying to
			// get unique name
			int commaIndex = 1;
			while (!classesWithSameShortenedName.isEmpty()) {

				List<RecoveredClass> leftoversWithSameShortName =
					new ArrayList<RecoveredClass>(classesWithSameShortenedName);

				// update all their shorted names to include up to the n'th comma
				Iterator<RecoveredClass> leftoversIterator = leftoversWithSameShortName.iterator();

				while (leftoversIterator.hasNext()) {

					monitor.checkCancelled();
					RecoveredClass currentClassWithSameShortName = leftoversIterator.next();
					currentClassWithSameShortName.addShortenedTemplatedName(
						getNewShortenedTemplateName(currentClassWithSameShortName, commaIndex));
				}

				// now iterate and see if any are unique and if so remove from list
				// if not, add up to next comma and so on until all are unique
				List<RecoveredClass> leftovers2WithSameShortName =
					new ArrayList<RecoveredClass>(classesWithSameShortenedName);
				Iterator<RecoveredClass> leftovers2Iterator =
					leftovers2WithSameShortName.iterator();

				while (leftovers2Iterator.hasNext()) {

					monitor.checkCancelled();
					RecoveredClass currentClassWithSameShortName = leftovers2Iterator.next();

					String shortenedTemplateName =
						currentClassWithSameShortName.getShortenedTemplateName();

					List<RecoveredClass> classesWithSameShortName =
						getClassesWithSameShortenedName(classesToProcess, shortenedTemplateName);

					if (classesWithSameShortName.size() == 1) {
						classesToProcess.remove(classesWithSameShortName.get(0));
						classesWithSameShortenedName.remove(classesWithSameShortName.get(0));
					}
				}

				commaIndex++;
			}

		}

	}

	/**
	 * Method to remove the template part of the given label name
	 * @param name the name of label
	 * @return the label name with template parts removed
	 */
	public String removeTemplate(String name) {
		int indexOfOpenTemplate = name.indexOf('<');
		String nameWithoutTemplates = name;
		if (indexOfOpenTemplate >= 0) {
			int indexOfCloseTemplate = name.lastIndexOf('>');
			if (indexOfCloseTemplate >= 0) {
				nameWithoutTemplates = name.substring(0, indexOfOpenTemplate) +
					name.substring(indexOfCloseTemplate, name.length() - 1);
			}
		}
		return nameWithoutTemplates;
	}

	public String getNewShortenedTemplateName(RecoveredClass recoveredClass, int commaIndex) {

		String className = recoveredClass.getName();

		int lastComma = 0;
		int nextComma = 0;
		while (commaIndex > 0) {
			nextComma = className.indexOf(",", lastComma);
			// if it gets to the end before the given commaIndex then we can't shorten
			// return whole thing
			if (nextComma == -1) {
				return recoveredClass.getName();
			}
			lastComma = nextComma + 1;
			commaIndex--;
		}

		String shortenedName = className.substring(0, nextComma) + "...>";
		return shortenedName;
	}

	public List<RecoveredClass> getClassesWithSameShortenedName(
			List<RecoveredClass> templateClasses, String shortenedName) throws CancelledException {

		List<RecoveredClass> classesWithSameShortenedName = new ArrayList<RecoveredClass>();

		Iterator<RecoveredClass> classIterator = templateClasses.iterator();
		while (classIterator.hasNext()) {
			monitor.checkCancelled();
			RecoveredClass currentClass = classIterator.next();

			if (currentClass.getShortenedTemplateName().equals(shortenedName)) {
				classesWithSameShortenedName.add(currentClass);
			}
		}
		return classesWithSameShortenedName;

	}

	/**
	 * Returns a hex string representation of the integer.
	 *
	 * @param i        the integer
	 * @param zeropad  true if the value should be zero padded
	 * @param header   true if "0x" should be prepended
	 * @return the hex formatted string
	 */
	// taken from GhidraScript
	public String toHexString(int i, boolean zeropad, boolean header) {
		String s = Integer.toHexString(i);
		if (zeropad) {
			s = zeropad(s, 8);
		}
		return (header ? "0x" : "") + s;
	}

	// taken from GhidraScript
	private static String zeropad(String s, int len) {
		if (s == null) {
			s = "";
		}
		StringBuffer buffer = new StringBuffer(s);
		int zerosNeeded = len - s.length();
		for (int i = 0; i < zerosNeeded; ++i) {
			buffer.insert(0, '0');
		}
		return buffer.toString();
	}


}
