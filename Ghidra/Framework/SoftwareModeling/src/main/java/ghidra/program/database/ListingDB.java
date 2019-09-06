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
package ghidra.program.database;

import java.util.*;

import ghidra.program.database.code.CodeManager;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.database.module.TreeManager;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.model.util.PropertyMap;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Database implementation of Listing.
 *
 *
 */
class ListingDB implements Listing {

	private ProgramDB program;
	private CodeManager codeMgr;
	private TreeManager treeMgr;
	private FunctionManager functionMgr;

	/**
	 * Set the program.
	 */
	public void setProgram(ProgramDB program) {
		this.program = program;
		codeMgr = program.getCodeManager();
		treeMgr = program.getTreeManager();
		functionMgr = program.getFunctionManager();
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getCodeUnitAt(ghidra.program.model.address.Address)
	 */
	@Override
	public CodeUnit getCodeUnitAt(Address addr) {
		return codeMgr.getCodeUnitAt(addr);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getCodeUnitContaining(ghidra.program.model.address.Address)
	 */
	@Override
	public CodeUnit getCodeUnitContaining(Address addr) {
		return codeMgr.getCodeUnitContaining(addr);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getCodeUnitAfter(ghidra.program.model.address.Address)
	 */
	@Override
	public CodeUnit getCodeUnitAfter(Address addr) {
		return codeMgr.getCodeUnitAfter(addr);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getCodeUnitBefore(ghidra.program.model.address.Address)
	 */
	@Override
	public CodeUnit getCodeUnitBefore(Address addr) {
		return codeMgr.getCodeUnitBefore(addr);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getCodeUnitIterator(java.lang.String)
	 */
	@Override
	public CodeUnitIterator getCodeUnitIterator(String property, boolean forward) {
		return codeMgr.getCodeUnitIterator(property, program.getMinAddress(), forward);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getCodeUnitIterator(java.lang.String, ghidra.program.model.address.Address)
	 */
	@Override
	public CodeUnitIterator getCodeUnitIterator(String property, Address addr, boolean forward) {
		return codeMgr.getCodeUnitIterator(property, addr, forward);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getCodeUnitIterator(java.lang.String, ghidra.program.model.address.AddressSetView)
	 */
	@Override
	public CodeUnitIterator getCodeUnitIterator(String property, AddressSetView addrSet,
			boolean forward) {
		return codeMgr.getCodeUnitIterator(property, addrSet, forward);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getCodeUnits()
	 */
	@Override
	public CodeUnitIterator getCodeUnits(boolean forward) {
		return codeMgr.getCodeUnits(program.getMemory(), forward);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getCodeUnits(ghidra.program.model.address.Address)
	 */
	@Override
	public CodeUnitIterator getCodeUnits(Address addr, boolean forward) {
		return codeMgr.getCodeUnits(addr, forward);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getCodeUnits(ghidra.program.model.address.AddressSetView)
	 */
	@Override
	public CodeUnitIterator getCodeUnits(AddressSetView addrSet, boolean forward) {
		return codeMgr.getCodeUnits(addrSet, forward);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getInstructionAt(ghidra.program.model.address.Address)
	 */
	@Override
	public Instruction getInstructionAt(Address addr) {
		return codeMgr.getInstructionAt(addr);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getInstructionContaining(ghidra.program.model.address.Address)
	 */
	@Override
	public Instruction getInstructionContaining(Address addr) {
		return codeMgr.getInstructionContaining(addr);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getInstructionAfter(ghidra.program.model.address.Address)
	 */
	@Override
	public Instruction getInstructionAfter(Address addr) {
		return codeMgr.getInstructionAfter(addr);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getInstructionBefore(ghidra.program.model.address.Address)
	 */
	@Override
	public Instruction getInstructionBefore(Address addr) {
		return codeMgr.getInstructionBefore(addr);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getInstructions()
	 */
	@Override
	public InstructionIterator getInstructions(boolean forward) {
		return codeMgr.getInstructions(forward ? program.getMinAddress() : program.getMaxAddress(),
			forward);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getInstructions(ghidra.program.model.address.Address)
	 */
	@Override
	public InstructionIterator getInstructions(Address addr, boolean forward) {
		return codeMgr.getInstructions(addr, forward);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getInstructions(ghidra.program.model.address.AddressSetView)
	 */
	@Override
	public InstructionIterator getInstructions(AddressSetView addrSet, boolean forward) {
		return codeMgr.getInstructions(addrSet, forward);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getDataAt(ghidra.program.model.address.Address)
	 */
	@Override
	public Data getDataAt(Address addr) {
		return codeMgr.getDataAt(addr);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getDataContaining(ghidra.program.model.address.Address)
	 */
	@Override
	public Data getDataContaining(Address addr) {
		return codeMgr.getDataContaining(addr);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getDataAfter(ghidra.program.model.address.Address)
	 */
	@Override
	public Data getDataAfter(Address addr) {
		return codeMgr.getDataAfter(addr);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getDataBefore(ghidra.program.model.address.Address)
	 */
	@Override
	public Data getDataBefore(Address addr) {
		return codeMgr.getDataBefore(addr);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getData()
	 */
	@Override
	public DataIterator getData(boolean forward) {
		return codeMgr.getData(forward ? program.getMinAddress() : program.getMaxAddress(),
			forward);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getData(ghidra.program.model.address.Address)
	 */
	@Override
	public DataIterator getData(Address addr, boolean forward) {
		return codeMgr.getData(addr, forward);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getData(ghidra.program.model.address.AddressSetView)
	 */
	@Override
	public DataIterator getData(AddressSetView addrSet, boolean forward) {
		return codeMgr.getData(addrSet, forward);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getDefinedDataAt(ghidra.program.model.address.Address)
	 */
	@Override
	public Data getDefinedDataAt(Address addr) {
		return codeMgr.getDefinedDataAt(addr);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getDefinedDataContaining(ghidra.program.model.address.Address)
	 */
	@Override
	public Data getDefinedDataContaining(Address addr) {
		return codeMgr.getDefinedDataContaining(addr);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getDefinedDataAfter(ghidra.program.model.address.Address)
	 */
	@Override
	public Data getDefinedDataAfter(Address addr) {
		return codeMgr.getDefinedDataAfter(addr);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getDefinedDataBefore(ghidra.program.model.address.Address)
	 */
	@Override
	public Data getDefinedDataBefore(Address addr) {
		return codeMgr.getDefinedDataBefore(addr);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getDefinedData()
	 */
	@Override
	public DataIterator getDefinedData(boolean forward) {
		return codeMgr.getDefinedData(forward ? program.getMinAddress() : program.getMaxAddress(),
			forward);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getDefinedData(ghidra.program.model.address.Address)
	 */
	@Override
	public DataIterator getDefinedData(Address addr, boolean forward) {
		return codeMgr.getDefinedData(addr, forward);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getDefinedData(ghidra.program.model.address.AddressSetView)
	 */
	@Override
	public DataIterator getDefinedData(AddressSetView addrSet, boolean forward) {
		return codeMgr.getDefinedData(addrSet, forward);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getUndefinedDataAt(ghidra.program.model.address.Address)
	 */
	@Override
	public Data getUndefinedDataAt(Address addr) {
		return codeMgr.getUndefinedAt(addr);
	}

	@Override
	public AddressSetView getUndefinedRanges(AddressSetView set, boolean initializedMemoryOnly,
			TaskMonitor monitor) throws CancelledException {
		return codeMgr.getUndefinedRanges(set, initializedMemoryOnly, monitor);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getUndefinedDataAfter(ghidra.program.model.address.Address)
	 */
	@Override
	public Data getUndefinedDataAfter(Address addr, TaskMonitor monitor) {
		return codeMgr.getFirstUndefinedDataAfter(addr, monitor);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getFirstUndefinedData(ghidra.program.model.address.AddressSetView)
	 */
	@Override
	public Data getFirstUndefinedData(AddressSetView set, TaskMonitor monitor) {
		return codeMgr.getFirstUndefinedData(set, monitor);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getUndefinedDataBefore(ghidra.program.model.address.Address)
	 */
	@Override
	public Data getUndefinedDataBefore(Address addr, TaskMonitor monitor) {
		return codeMgr.getFirstUndefinedDataBefore(addr, monitor);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getCompositeData()
	 */
	@Override
	public DataIterator getCompositeData(boolean forward) {
		return codeMgr.getCompositeData(forward ? program.getMinAddress() : program.getMaxAddress(),
			forward);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getCompositeData(ghidra.program.model.address.Address)
	 */
	@Override
	public DataIterator getCompositeData(Address start, boolean forward) {
		return codeMgr.getCompositeData(start, forward);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getCompositeData(ghidra.program.model.address.AddressSetView)
	 */
	@Override
	public DataIterator getCompositeData(AddressSetView addrSet, boolean forward) {
		return codeMgr.getCompositeData(addrSet, forward);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getUserDefinedProperties()
	 */
	@Override
	public Iterator<String> getUserDefinedProperties() {
		return codeMgr.getUserDefinedProperties();
	}

	/**
	 * @see ghidra.program.model.listing.Listing#removeUserDefinedProperty(java.lang.String)
	 */
	@Override
	public void removeUserDefinedProperty(String propertyName) {
		codeMgr.removeUserDefinedProperty(propertyName);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getPropertyMap(java.lang.String)
	 */
	@Override
	public PropertyMap getPropertyMap(String propertyName) {
		return codeMgr.getPropertyMap(propertyName);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#createInstruction(ghidra.program.model.address.Address, ghidra.program.model.lang.InstructionPrototype, ghidra.program.model.mem.MemBuffer, ghidra.program.model.lang.ProcessorContext)
	 */
	@Override
	public Instruction createInstruction(Address addr, InstructionPrototype prototype,
			MemBuffer memBuf, ProcessorContextView context) throws CodeUnitInsertionException {
		return codeMgr.createCodeUnit(addr, prototype, memBuf, context);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#addInstructions(ghidra.program.model.lang.InstructionSet, boolean)
	 */
	@Override
	public AddressSetView addInstructions(InstructionSet instructionSet, boolean overwrite)
			throws CodeUnitInsertionException {
		return codeMgr.addInstructions(instructionSet, overwrite);
	}

	/**
	 *
	 * @see ghidra.program.model.listing.Listing#createData(ghidra.program.model.address.Address, ghidra.program.model.data.DataType)
	 */
	@Override
	public Data createData(Address addr, DataType dataType)
			throws CodeUnitInsertionException, DataTypeConflictException {
		return codeMgr.createCodeUnit(addr, dataType, dataType.getLength());
	}

	/**
	 * @see ghidra.program.model.listing.Listing#createData(ghidra.program.model.address.Address, ghidra.program.model.data.DataType)
	 */
	@Override
	public Data createData(Address addr, DataType dataType, int length)
			throws CodeUnitInsertionException, DataTypeConflictException {
		return codeMgr.createCodeUnit(addr, dataType, length);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#clearCodeUnits(ghidra.program.model.address.Address, ghidra.program.model.address.Address, boolean)
	 */
	@Override
	public void clearCodeUnits(Address startAddr, Address endAddr, boolean clearContext) {
		try {
			codeMgr.clearCodeUnits(startAddr, endAddr, clearContext,
				TaskMonitorAdapter.DUMMY_MONITOR);
		}
		catch (CancelledException e) {
		}
	}

	/**
	 * @see ghidra.program.model.listing.Listing#clearCodeUnits(ghidra.program.model.address.Address, ghidra.program.model.address.Address, boolean, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void clearCodeUnits(Address startAddr, Address endAddr, boolean clearContext,
			TaskMonitor monitor) throws CancelledException {
		codeMgr.clearCodeUnits(startAddr, endAddr, clearContext, monitor);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#isUndefined(ghidra.program.model.address.Address, ghidra.program.model.address.Address)
	 */
	@Override
	public boolean isUndefined(Address start, Address end) {
		return codeMgr.isUndefined(start, end);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#clearComments(ghidra.program.model.address.Address, ghidra.program.model.address.Address)
	 */
	@Override
	public void clearComments(Address startAddr, Address endAddr) {
		codeMgr.clearComments(startAddr, endAddr);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#clearProperties(ghidra.program.model.address.Address, ghidra.program.model.address.Address)
	 */
	@Override
	public void clearProperties(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException {
		codeMgr.clearProperties(startAddr, endAddr, monitor);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#clearAll(boolean, TaskMonitor)
	 */
	@Override
	public void clearAll(boolean clearContext, TaskMonitor monitor) {
		codeMgr.clearAll(false, TaskMonitorAdapter.DUMMY_MONITOR);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getNumCodeUnits()
	 */
	@Override
	public long getNumCodeUnits() {
		return getNumDefinedData() + getNumInstructions();
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getNumDefinedData()
	 */
	@Override
	public long getNumDefinedData() {
		return codeMgr.getNumDefinedData();
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getNumInstructions()
	 */
	@Override
	public long getNumInstructions() {
		return codeMgr.getNumInstructions();
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getFragment(java.lang.String, ghidra.program.model.address.Address)
	 */
	@Override
	public ProgramFragment getFragment(String treeName, Address addr) {
		return treeMgr.getFragment(treeName, addr);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getModule(java.lang.String, java.lang.String)
	 */
	@Override
	public ProgramModule getModule(String treeName, String name) {
		return treeMgr.getModule(treeName, name);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getFragment(java.lang.String, java.lang.String)
	 */
	@Override
	public ProgramFragment getFragment(String treeName, String name) {
		return treeMgr.getFragment(treeName, name);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#createRootModule(java.lang.String)
	 */
	@Override
	public ProgramModule createRootModule(String treeName) throws DuplicateNameException {
		return treeMgr.createRootModule(treeName);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getRootModule(java.lang.String)
	 */
	@Override
	public ProgramModule getRootModule(String treeName) {
		return treeMgr.getRootModule(treeName);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getRootModule(long)
	 */
	@Override
	public ProgramModule getRootModule(long treeID) {
		return treeMgr.getRootModule(treeID);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getRootModule(long)
	 */
	@Override
	public ProgramModule getDefaultRootModule() {
		return treeMgr.getDefaultRootModule();
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getTreeNames()
	 */
	@Override
	public String[] getTreeNames() {
		return treeMgr.getTreeNames();
	}

	/**
	 * @see ghidra.program.model.listing.Listing#removeTree(java.lang.String)
	 */
	@Override
	public boolean removeTree(String treeName) {
		return treeMgr.removeTree(treeName);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#renameTree(java.lang.String, java.lang.String)
	 */
	@Override
	public void renameTree(String oldName, String newName) throws DuplicateNameException {
		treeMgr.renameTree(oldName, newName);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getDataTypeManager()
	 */
	@Override
	public DataTypeManager getDataTypeManager() {
		return program.getDataTypeManager();
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.listing.Listing#createFunction(java.lang.String, ghidra.program.model.address.Address, ghidra.program.model.address.AddressSetView, int)
	 */
	@Override
	public Function createFunction(String name, Address entryPoint, AddressSetView body,
			SourceType source) throws InvalidInputException, OverlappingFunctionException {
		return functionMgr.createFunction(name, entryPoint, body, source);
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.listing.Listing#createFunction(java.lang.String, ghidra.program.model.symbol.Namespace, ghidra.program.model.address.Address, ghidra.program.model.address.AddressSetView, int)
	 */
	@Override
	public Function createFunction(String name, Namespace nameSpace, Address entryPoint,
			AddressSetView body, SourceType source)
			throws InvalidInputException, OverlappingFunctionException {
		return functionMgr.createFunction(name, nameSpace, entryPoint, body, source);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#removeFunction(ghidra.program.model.address.Address)
	 */
	@Override
	public void removeFunction(Address entryPoint) {
		functionMgr.removeFunction(entryPoint);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getFunctionAt(ghidra.program.model.address.Address)
	 */
	@Override
	public Function getFunctionAt(Address entryPoint) {
		return functionMgr.getFunctionAt(entryPoint);
	}

	@Override
	public List<Function> getGlobalFunctions(String name) {
		List<Function> list = new ArrayList<>();
		List<Symbol> globalSymbols = program.getSymbolTable().getGlobalSymbols(name);
		for (Symbol symbol : globalSymbols) {
			if (symbol.getSymbolType() == SymbolType.FUNCTION) {
				list.add((Function) symbol.getObject());
			}
		}
		return list;
	}

	@Override
	public List<Function> getFunctions(String namespacePath, String name) {
		List<Function> list = new ArrayList<>();
		SymbolIterator symbols = program.getSymbolTable().getSymbols(name);
		while (symbols.hasNext()) {
			Symbol symbol = symbols.next();
			if (symbol instanceof FunctionSymbol) {
				Namespace namespace = symbol.getParentNamespace();
				String fullName = namespace.getName(true);
				if (fullName.equals(namespacePath)) {
					list.add((Function) symbol.getObject());
				}
			}
		}
		return list;
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getFirstFunctionContaining(ghidra.program.model.address.Address)
	 */
	@Override
	public Function getFunctionContaining(Address addr) {
		return functionMgr.getFunctionContaining(addr);
	}

	@Override
	public FunctionIterator getExternalFunctions() {
		return functionMgr.getExternalFunctions();
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getFunctions(boolean)
	 */
	@Override
	public FunctionIterator getFunctions(boolean forward) {
		return functionMgr.getFunctions(forward);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getFunctions(ghidra.program.model.address.Address, boolean)
	 */
	@Override
	public FunctionIterator getFunctions(Address start, boolean forward) {
		return functionMgr.getFunctions(start, forward);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getFunctions(ghidra.program.model.address.AddressSetView, boolean)
	 */
	@Override
	public FunctionIterator getFunctions(AddressSetView asv, boolean forward) {
		return functionMgr.getFunctions(asv, forward);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#isInFunction(ghidra.program.model.address.Address)
	 */
	@Override
	public boolean isInFunction(Address addr) {
		return functionMgr.isInFunction(addr);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getCommentHistory(ghidra.program.model.address.Address, int)
	 */
	@Override
	public CommentHistory[] getCommentHistory(Address addr, int commentType) {
		return codeMgr.getCommentHistory(addr, commentType);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getCommentCodeUnitIterator(int, ghidra.program.model.address.AddressSetView)
	 */
	@Override
	public CodeUnitIterator getCommentCodeUnitIterator(int commentType, AddressSetView addrSet) {
		return codeMgr.getCommentCodeUnitIterator(commentType, addrSet);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getCommentAddressIterator(int, ghidra.program.model.address.AddressSetView, boolean)
	 */
	@Override
	public AddressIterator getCommentAddressIterator(int commentType, AddressSetView addrSet,
			boolean forward) {
		return codeMgr.getCommentAddressIterator(commentType, addrSet, forward);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getCommentAddressIterator(ghidra.program.model.address.AddressSetView, boolean)
	 */
	@Override
	public AddressIterator getCommentAddressIterator(AddressSetView addrSet, boolean forward) {
		return codeMgr.getCommentAddressIterator(addrSet, forward);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getComment(int, ghidra.program.model.address.Address)
	 */
	@Override
	public String getComment(int commentType, Address address) {
		return codeMgr.getComment(commentType, address);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#setComment(ghidra.program.model.address.Address, int, java.lang.String)
	 */
	@Override
	public void setComment(Address address, int commentType, String comment) {
		codeMgr.setComment(address, commentType, comment);
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getDefinedCodeUnitAfter(ghidra.program.model.address.Address)
	 */
	@Override
	public CodeUnit getDefinedCodeUnitAfter(Address addr) {
		CodeUnit data = codeMgr.getDefinedDataAfter(addr);
		CodeUnit inst = codeMgr.getInstructionAfter(addr);
		if (data == null) {
			return inst;
		}
		else if (inst == null) {
			return data;
		}
		Address dataAddr = data.getMinAddress();
		Address instAddr = inst.getMinAddress();
		if (dataAddr.compareTo(instAddr) < 0) {
			return data;
		}
		return inst;
	}

	/**
	 * @see ghidra.program.model.listing.Listing#getDefinedCodeUnitBefore(ghidra.program.model.address.Address)
	 */
	@Override
	public CodeUnit getDefinedCodeUnitBefore(Address addr) {
		CodeUnit data = codeMgr.getDefinedDataBefore(addr);
		CodeUnit inst = codeMgr.getInstructionBefore(addr);
		if (data == null) {
			return inst;
		}
		else if (inst == null) {
			return data;
		}
		Address dataAddr = data.getMinAddress();
		Address instAddr = inst.getMinAddress();
		if (dataAddr.compareTo(instAddr) < 0) {
			return inst;
		}
		return data;
	}

}
