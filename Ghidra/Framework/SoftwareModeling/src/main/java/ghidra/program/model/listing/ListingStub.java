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
package ghidra.program.model.listing;

import java.util.Iterator;
import java.util.List;

import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.model.util.PropertyMap;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * ListingStub can be extended for use by tests. It throws an UnsupportedOperationException
 * for all methods in the Listing interface. Any method that is needed for your test can then
 * be overridden so it can provide its own test implementation and return value.
 */
public class ListingStub implements Listing {

	@Override
	public CodeUnit getCodeUnitAt(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public CodeUnit getCodeUnitContaining(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public CodeUnit getCodeUnitAfter(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public CodeUnit getCodeUnitBefore(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public CodeUnitIterator getCodeUnitIterator(String property, boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public CodeUnitIterator getCodeUnitIterator(String property, Address addr, boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public CodeUnitIterator getCodeUnitIterator(String property, AddressSetView addrSet,
			boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public CodeUnitIterator getCommentCodeUnitIterator(int commentType, AddressSetView addrSet) {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressIterator getCommentAddressIterator(int commentType, AddressSetView addrSet,
			boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressIterator getCommentAddressIterator(AddressSetView addrSet, boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getComment(int commentType, Address address) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setComment(Address address, int commentType, String comment) {
		throw new UnsupportedOperationException();
	}

	@Override
	public CodeUnitIterator getCodeUnits(boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public CodeUnitIterator getCodeUnits(Address addr, boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public CodeUnitIterator getCodeUnits(AddressSetView addrSet, boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Instruction getInstructionAt(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Instruction getInstructionContaining(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Instruction getInstructionAfter(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Instruction getInstructionBefore(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public InstructionIterator getInstructions(boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public InstructionIterator getInstructions(Address addr, boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public InstructionIterator getInstructions(AddressSetView addrSet, boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Data getDataAt(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Data getDataContaining(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Data getDataAfter(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Data getDataBefore(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataIterator getData(boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataIterator getData(Address addr, boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataIterator getData(AddressSetView addrSet, boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Data getDefinedDataAt(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Data getDefinedDataContaining(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Data getDefinedDataAfter(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Data getDefinedDataBefore(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataIterator getDefinedData(boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataIterator getDefinedData(Address addr, boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataIterator getDefinedData(AddressSetView addrSet, boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Data getUndefinedDataAt(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Data getUndefinedDataAfter(Address addr, TaskMonitor monitor) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Data getFirstUndefinedData(AddressSetView set, TaskMonitor monitor) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Data getUndefinedDataBefore(Address addr, TaskMonitor monitor) {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressSetView getUndefinedRanges(AddressSetView set, boolean initializedMemoryOnly,
			TaskMonitor monitor) throws CancelledException {
		throw new UnsupportedOperationException();
	}

	@Override
	public CodeUnit getDefinedCodeUnitAfter(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public CodeUnit getDefinedCodeUnitBefore(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataIterator getCompositeData(boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataIterator getCompositeData(Address start, boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataIterator getCompositeData(AddressSetView addrSet, boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Iterator<String> getUserDefinedProperties() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeUserDefinedProperty(String propertyName) {
		throw new UnsupportedOperationException();
	}

	@Override
	public PropertyMap getPropertyMap(String propertyName) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Instruction createInstruction(Address addr, InstructionPrototype prototype,
			MemBuffer memBuf, ProcessorContextView context) throws CodeUnitInsertionException {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressSetView addInstructions(InstructionSet instructionSet, boolean overwrite)
			throws CodeUnitInsertionException {
		throw new UnsupportedOperationException();
	}

	@Override
	public Data createData(Address addr, DataType dataType, int length)
			throws CodeUnitInsertionException, DataTypeConflictException {
		throw new UnsupportedOperationException();
	}

	@Override
	public Data createData(Address addr, DataType dataType)
			throws CodeUnitInsertionException, DataTypeConflictException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void clearCodeUnits(Address startAddr, Address endAddr, boolean clearContext) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void clearCodeUnits(Address startAddr, Address endAddr, boolean clearContext,
			TaskMonitor monitor) throws CancelledException {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isUndefined(Address start, Address end) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void clearComments(Address startAddr, Address endAddr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void clearProperties(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void clearAll(boolean clearContext, TaskMonitor monitor) {
		throw new UnsupportedOperationException();
	}

	@Override
	public ProgramFragment getFragment(String treeName, Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public ProgramModule getModule(String treeName, String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public ProgramModule getDefaultRootModule() {
		throw new UnsupportedOperationException();
	}

	@Override
	public ProgramFragment getFragment(String treeName, String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public ProgramModule createRootModule(String treeName) throws DuplicateNameException {
		throw new UnsupportedOperationException();
	}

	@Override
	public ProgramModule getRootModule(String treeName) {
		throw new UnsupportedOperationException();
	}

	@Override
	public ProgramModule getRootModule(long treeID) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String[] getTreeNames() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean removeTree(String treeName) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void renameTree(String oldName, String newName) throws DuplicateNameException {
		throw new UnsupportedOperationException();
	}

	@Override
	public long getNumCodeUnits() {
		throw new UnsupportedOperationException();
	}

	@Override
	public long getNumDefinedData() {
		throw new UnsupportedOperationException();
	}

	@Override
	public long getNumInstructions() {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataTypeManager getDataTypeManager() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Function createFunction(String name, Address entryPoint, AddressSetView body,
			SourceType source) throws InvalidInputException, OverlappingFunctionException {
		throw new UnsupportedOperationException();
	}

	@Override
	public Function createFunction(String name, Namespace nameSpace, Address entryPoint,
			AddressSetView body, SourceType source)
			throws InvalidInputException, OverlappingFunctionException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeFunction(Address entryPoint) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Function getFunctionAt(Address entryPoint) {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<Function> getFunctions(String namespace, String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Function getFunctionContaining(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public FunctionIterator getExternalFunctions() {
		throw new UnsupportedOperationException();
	}

	@Override
	public FunctionIterator getFunctions(boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public FunctionIterator getFunctions(Address start, boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public FunctionIterator getFunctions(AddressSetView asv, boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isInFunction(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public CommentHistory[] getCommentHistory(Address addr, int commentType) {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<Function> getGlobalFunctions(String name) {
		throw new UnsupportedOperationException();
	}

}
