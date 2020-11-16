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
package ghidra.program.model;

import java.io.IOException;
import java.util.Iterator;
import java.util.List;

import ghidra.program.database.ProgramDB;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class FunctionManagerTestDouble implements FunctionManager {

	@Override
	public ProgramDB getProgram() {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<String> getCallingConventionNames() {
		throw new UnsupportedOperationException();
	}

	@Override
	public PrototypeModel getDefaultCallingConvention() {
		throw new UnsupportedOperationException();
	}

	@Override
	public PrototypeModel getCallingConvention(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public PrototypeModel[] getCallingConventions() {
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
	public Function createThunkFunction(String name, Namespace nameSpace, Address entryPoint,
			AddressSetView body, Function thunkedFunction, SourceType source)
			throws OverlappingFunctionException {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getFunctionCount() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean removeFunction(Address entryPoint) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Function getFunctionAt(Address entryPoint) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Function getFunctionContaining(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public FunctionIterator getFunctions(boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public FunctionIterator getFunctions(Address start, boolean foward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public FunctionIterator getFunctions(AddressSetView asv, boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public FunctionIterator getFunctionsNoStubs(boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public FunctionIterator getFunctionsNoStubs(Address start, boolean foward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public FunctionIterator getFunctionsNoStubs(AddressSetView asv, boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public FunctionIterator getExternalFunctions() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isInFunction(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void deleteAddressRange(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException {
		throw new UnsupportedOperationException();
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
		throw new UnsupportedOperationException();
	}

	@Override
	public Iterator<Function> getFunctionsOverlapping(AddressSetView set) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Variable getReferencedVariable(Address instrAddr, Address storageAddr, int size,
			boolean isRead) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Function getFunction(long key) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Function getReferencedFunction(Address address) {
		throw new UnsupportedOperationException();
	}

	@Override
	public FunctionTagManager getFunctionTagManager() {
		throw new UnsupportedOperationException();
	}
}
