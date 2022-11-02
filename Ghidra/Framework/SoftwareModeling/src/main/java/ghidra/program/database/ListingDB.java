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

/**
 * Database implementation of Listing.
 */
class ListingDB implements Listing {

	private ProgramDB program;
	private CodeManager codeMgr;
	private TreeManager treeMgr;
	private FunctionManager functionMgr;

	public void setProgram(ProgramDB program) {
		this.program = program;
		codeMgr = program.getCodeManager();
		treeMgr = program.getTreeManager();
		functionMgr = program.getFunctionManager();
	}

	@Override
	public CodeUnit getCodeUnitAt(Address addr) {
		return codeMgr.getCodeUnitAt(addr);
	}

	@Override
	public CodeUnit getCodeUnitContaining(Address addr) {
		return codeMgr.getCodeUnitContaining(addr);
	}

	@Override
	public CodeUnit getCodeUnitAfter(Address addr) {
		return codeMgr.getCodeUnitAfter(addr);
	}

	@Override
	public CodeUnit getCodeUnitBefore(Address addr) {
		return codeMgr.getCodeUnitBefore(addr);
	}

	@Override
	public CodeUnitIterator getCodeUnitIterator(String property, boolean forward) {
		return codeMgr.getCodeUnitIterator(property, program.getMinAddress(), forward);
	}

	@Override
	public CodeUnitIterator getCodeUnitIterator(String property, Address addr, boolean forward) {
		return codeMgr.getCodeUnitIterator(property, addr, forward);
	}

	@Override
	public CodeUnitIterator getCodeUnitIterator(String property, AddressSetView addrSet,
			boolean forward) {
		return codeMgr.getCodeUnitIterator(property, addrSet, forward);
	}

	@Override
	public CodeUnitIterator getCodeUnits(boolean forward) {
		return codeMgr.getCodeUnits(program.getMemory(), forward);
	}

	@Override
	public CodeUnitIterator getCodeUnits(Address addr, boolean forward) {
		return codeMgr.getCodeUnits(addr, forward);
	}

	@Override
	public CodeUnitIterator getCodeUnits(AddressSetView addrSet, boolean forward) {
		return codeMgr.getCodeUnits(addrSet, forward);
	}

	@Override
	public Instruction getInstructionAt(Address addr) {
		return codeMgr.getInstructionAt(addr);
	}

	@Override
	public Instruction getInstructionContaining(Address addr) {
		return codeMgr.getInstructionContaining(addr);
	}

	@Override
	public Instruction getInstructionAfter(Address addr) {
		return codeMgr.getInstructionAfter(addr);
	}

	@Override
	public Instruction getInstructionBefore(Address addr) {
		return codeMgr.getInstructionBefore(addr);
	}

	@Override
	public InstructionIterator getInstructions(boolean forward) {
		return codeMgr.getInstructions(forward ? program.getMinAddress() : program.getMaxAddress(),
			forward);
	}

	@Override
	public InstructionIterator getInstructions(Address addr, boolean forward) {
		return codeMgr.getInstructions(addr, forward);
	}

	@Override
	public InstructionIterator getInstructions(AddressSetView addrSet, boolean forward) {
		return codeMgr.getInstructions(addrSet, forward);
	}

	@Override
	public Data getDataAt(Address addr) {
		return codeMgr.getDataAt(addr);
	}

	@Override
	public Data getDataContaining(Address addr) {
		return codeMgr.getDataContaining(addr);
	}

	@Override
	public Data getDataAfter(Address addr) {
		return codeMgr.getDataAfter(addr);
	}

	@Override
	public Data getDataBefore(Address addr) {
		return codeMgr.getDataBefore(addr);
	}

	@Override
	public DataIterator getData(boolean forward) {
		return codeMgr.getData(forward ? program.getMinAddress() : program.getMaxAddress(),
			forward);
	}

	@Override
	public DataIterator getData(Address addr, boolean forward) {
		return codeMgr.getData(addr, forward);
	}

	@Override
	public DataIterator getData(AddressSetView addrSet, boolean forward) {
		return codeMgr.getData(addrSet, forward);
	}

	@Override
	public Data getDefinedDataAt(Address addr) {
		return codeMgr.getDefinedDataAt(addr);
	}

	@Override
	public Data getDefinedDataContaining(Address addr) {
		return codeMgr.getDefinedDataContaining(addr);
	}

	@Override
	public Data getDefinedDataAfter(Address addr) {
		return codeMgr.getDefinedDataAfter(addr);
	}

	@Override
	public Data getDefinedDataBefore(Address addr) {
		return codeMgr.getDefinedDataBefore(addr);
	}

	@Override
	public DataIterator getDefinedData(boolean forward) {
		return codeMgr.getDefinedData(forward ? program.getMinAddress() : program.getMaxAddress(),
			forward);
	}

	@Override
	public DataIterator getDefinedData(Address addr, boolean forward) {
		return codeMgr.getDefinedData(addr, forward);
	}

	@Override
	public DataIterator getDefinedData(AddressSetView addrSet, boolean forward) {
		return codeMgr.getDefinedData(addrSet, forward);
	}

	@Override
	public Data getUndefinedDataAt(Address addr) {
		return codeMgr.getUndefinedAt(addr);
	}

	@Override
	public AddressSetView getUndefinedRanges(AddressSetView set, boolean initializedMemoryOnly,
			TaskMonitor monitor) throws CancelledException {
		return codeMgr.getUndefinedRanges(set, initializedMemoryOnly, monitor);
	}

	@Override
	public Data getUndefinedDataAfter(Address addr, TaskMonitor monitor) {
		return codeMgr.getFirstUndefinedDataAfter(addr, monitor);
	}

	@Override
	public Data getFirstUndefinedData(AddressSetView set, TaskMonitor monitor) {
		return codeMgr.getFirstUndefinedData(set, monitor);
	}

	@Override
	public Data getUndefinedDataBefore(Address addr, TaskMonitor monitor) {
		return codeMgr.getFirstUndefinedDataBefore(addr, monitor);
	}

	@Override
	public DataIterator getCompositeData(boolean forward) {
		return codeMgr.getCompositeData(forward ? program.getMinAddress() : program.getMaxAddress(),
			forward);
	}

	@Override
	public DataIterator getCompositeData(Address start, boolean forward) {
		return codeMgr.getCompositeData(start, forward);
	}

	@Override
	public DataIterator getCompositeData(AddressSetView addrSet, boolean forward) {
		return codeMgr.getCompositeData(addrSet, forward);
	}

	@Override
	public Iterator<String> getUserDefinedProperties() {
		return codeMgr.getUserDefinedProperties();
	}

	@Override
	public void removeUserDefinedProperty(String propertyName) {
		codeMgr.removeUserDefinedProperty(propertyName);
	}

	@Override
	public PropertyMap getPropertyMap(String propertyName) {
		return codeMgr.getPropertyMap(propertyName);
	}

	@Override
	public Instruction createInstruction(Address addr, InstructionPrototype prototype,
			MemBuffer memBuf, ProcessorContextView context) throws CodeUnitInsertionException {
		return codeMgr.createCodeUnit(addr, prototype, memBuf, context);
	}

	@Override
	public AddressSetView addInstructions(InstructionSet instructionSet, boolean overwrite)
			throws CodeUnitInsertionException {
		return codeMgr.addInstructions(instructionSet, overwrite);
	}

	@Override
	public Data createData(Address addr, DataType dataType)
			throws CodeUnitInsertionException {
		return codeMgr.createCodeUnit(addr, dataType, dataType.getLength());
	}

	@Override
	public Data createData(Address addr, DataType dataType, int length)
			throws CodeUnitInsertionException {
		return codeMgr.createCodeUnit(addr, dataType, length);
	}

	@Override
	public void clearCodeUnits(Address startAddr, Address endAddr, boolean clearContext) {
		try {
			codeMgr.clearCodeUnits(startAddr, endAddr, clearContext,
				TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			// can't happen with dummy monitor
		}
	}

	@Override
	public void clearCodeUnits(Address startAddr, Address endAddr, boolean clearContext,
			TaskMonitor monitor) throws CancelledException {
		codeMgr.clearCodeUnits(startAddr, endAddr, clearContext, monitor);
	}

	@Override
	public boolean isUndefined(Address start, Address end) {
		return codeMgr.isUndefined(start, end);
	}

	@Override
	public void clearComments(Address startAddr, Address endAddr) {
		codeMgr.clearComments(startAddr, endAddr);
	}

	@Override
	public void clearProperties(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException {
		codeMgr.clearProperties(startAddr, endAddr, monitor);
	}

	@Override
	public void clearAll(boolean clearContext, TaskMonitor monitor) {
		codeMgr.clearAll(false, TaskMonitor.DUMMY);
	}

	@Override
	public long getNumCodeUnits() {
		return getNumDefinedData() + getNumInstructions();
	}

	@Override
	public long getNumDefinedData() {
		return codeMgr.getNumDefinedData();
	}

	@Override
	public long getNumInstructions() {
		return codeMgr.getNumInstructions();
	}

	@Override
	public ProgramFragment getFragment(String treeName, Address addr) {
		return treeMgr.getFragment(treeName, addr);
	}

	@Override
	public ProgramModule getModule(String treeName, String name) {
		return treeMgr.getModule(treeName, name);
	}

	@Override
	public ProgramFragment getFragment(String treeName, String name) {
		return treeMgr.getFragment(treeName, name);
	}

	@Override
	public ProgramModule createRootModule(String treeName) throws DuplicateNameException {
		return treeMgr.createRootModule(treeName);
	}

	@Override
	public ProgramModule getRootModule(String treeName) {
		return treeMgr.getRootModule(treeName);
	}

	@Override
	public ProgramModule getRootModule(long treeID) {
		return treeMgr.getRootModule(treeID);
	}

	@Override
	public ProgramModule getDefaultRootModule() {
		return treeMgr.getDefaultRootModule();
	}

	@Override
	public String[] getTreeNames() {
		return treeMgr.getTreeNames();
	}

	@Override
	public boolean removeTree(String treeName) {
		return treeMgr.removeTree(treeName);
	}

	@Override
	public void renameTree(String oldName, String newName) throws DuplicateNameException {
		treeMgr.renameTree(oldName, newName);
	}

	@Override
	public DataTypeManager getDataTypeManager() {
		return program.getDataTypeManager();
	}

	@Override
	public Function createFunction(String name, Address entryPoint, AddressSetView body,
			SourceType source) throws InvalidInputException, OverlappingFunctionException {
		return functionMgr.createFunction(name, entryPoint, body, source);
	}

	@Override
	public Function createFunction(String name, Namespace nameSpace, Address entryPoint,
			AddressSetView body, SourceType source)
			throws InvalidInputException, OverlappingFunctionException {
		return functionMgr.createFunction(name, nameSpace, entryPoint, body, source);
	}

	@Override
	public void removeFunction(Address entryPoint) {
		functionMgr.removeFunction(entryPoint);
	}

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

	@Override
	public Function getFunctionContaining(Address addr) {
		return functionMgr.getFunctionContaining(addr);
	}

	@Override
	public FunctionIterator getExternalFunctions() {
		return functionMgr.getExternalFunctions();
	}

	@Override
	public FunctionIterator getFunctions(boolean forward) {
		return functionMgr.getFunctions(forward);
	}

	@Override
	public FunctionIterator getFunctions(Address start, boolean forward) {
		return functionMgr.getFunctions(start, forward);
	}

	@Override
	public FunctionIterator getFunctions(AddressSetView asv, boolean forward) {
		return functionMgr.getFunctions(asv, forward);
	}

	@Override
	public boolean isInFunction(Address addr) {
		return functionMgr.isInFunction(addr);
	}

	@Override
	public CommentHistory[] getCommentHistory(Address addr, int commentType) {
		return codeMgr.getCommentHistory(addr, commentType);
	}

	@Override
	public CodeUnitIterator getCommentCodeUnitIterator(int commentType, AddressSetView addrSet) {
		return codeMgr.getCommentCodeUnitIterator(commentType, addrSet);
	}

	@Override
	public AddressIterator getCommentAddressIterator(int commentType, AddressSetView addrSet,
			boolean forward) {
		return codeMgr.getCommentAddressIterator(commentType, addrSet, forward);
	}

	@Override
	public AddressIterator getCommentAddressIterator(AddressSetView addrSet, boolean forward) {
		return codeMgr.getCommentAddressIterator(addrSet, forward);
	}

	@Override
	public String getComment(int commentType, Address address) {
		return codeMgr.getComment(commentType, address);
	}

	@Override
	public void setComment(Address address, int commentType, String comment) {
		codeMgr.setComment(address, commentType, comment);
	}

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
