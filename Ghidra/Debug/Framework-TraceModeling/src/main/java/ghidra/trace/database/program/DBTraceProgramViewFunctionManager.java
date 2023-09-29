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
package ghidra.trace.database.program;

import java.io.IOException;
import java.util.*;
import java.util.stream.Stream;

import ghidra.program.database.ProgramDB;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.trace.database.symbol.DBTraceNamespaceSymbol;
import ghidra.trace.util.EmptyFunctionIterator;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class DBTraceProgramViewFunctionManager implements FunctionManager {

	protected final DBTraceProgramView program;
	protected final DBTraceNamespaceSymbol global;

	public DBTraceProgramViewFunctionManager(DBTraceProgramView program) {
		this.program = program;
		this.global = program.trace.getSymbolManager().getGlobalNamespace();
	}

	@Override
	public Program getProgram() {
		return program;
	}

	@Override
	public FunctionTagManager getFunctionTagManager() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Collection<String> getCallingConventionNames() {
		return Stream.of(program.trace.getBaseCompilerSpec().getCallingConventions())
				.map(PrototypeModel::getName)
				.toList();
	}

	@Override
	public PrototypeModel getDefaultCallingConvention() {
		return program.trace.getBaseCompilerSpec().getDefaultCallingConvention();
	}

	@Override
	public PrototypeModel getCallingConvention(String name) {
		return program.trace.getBaseCompilerSpec().getCallingConvention(name);
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
	public Function createThunkFunction(String name, Namespace nameSpace, Address entryPoint,
			AddressSetView body, Function thunkedFunction, SourceType source)
			throws OverlappingFunctionException {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getFunctionCount() {
		return 0;
	}

	@Override
	public boolean removeFunction(Address entryPoint) {
		return false;
	}

	@Override
	public Function getFunctionAt(Address entryPoint) {
		return null;
	}

	@Override
	public Function getReferencedFunction(Address address) {
		return null;
	}

	@Override
	public Function getFunctionContaining(Address addr) {
		return null;
	}

	@Override
	public FunctionIterator getFunctions(boolean forward) {
		return getFunctions(program.getAddressFactory().getAddressSet(), forward);
	}

	@Override
	public FunctionIterator getFunctions(Address start, boolean forward) {
		return EmptyFunctionIterator.INSTANCE;
	}

	@Override
	public FunctionIterator getFunctions(AddressSetView asv, boolean forward) {
		return EmptyFunctionIterator.INSTANCE;
	}

	@Override
	public FunctionIterator getFunctionsNoStubs(boolean forward) {
		return EmptyFunctionIterator.INSTANCE;
	}

	@Override
	public FunctionIterator getFunctionsNoStubs(Address start, boolean forward) {
		return EmptyFunctionIterator.INSTANCE;
	}

	@Override
	public FunctionIterator getFunctionsNoStubs(AddressSetView asv, boolean forward) {
		return EmptyFunctionIterator.INSTANCE;
	}

	@Override
	public FunctionIterator getExternalFunctions() {
		return EmptyFunctionIterator.INSTANCE;
	}

	@Override
	public boolean isInFunction(Address addr) {
		return false;
	}

	@Override
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void deleteAddressRange(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException {
		// Do nothing
	}

	@Override
	public void setProgram(ProgramDB program) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void programReady(int openMode, int currentRevision, TaskMonitor monitor)
			throws IOException, CancelledException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void invalidateCache(boolean all) {
		// Do nothing
	}

	@Override
	public Iterator<Function> getFunctionsOverlapping(AddressSetView set) {
		return Collections.emptyIterator();
	}

	@Override
	public Variable getReferencedVariable(Address instrAddr, Address storageAddr, int size,
			boolean isRead) {
		return null;
	}

	@Override
	public Function getFunction(long key) {
		return null;
	}
}
