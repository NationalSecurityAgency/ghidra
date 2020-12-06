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
package ghidra.javaclass.format;

import java.io.IOException;
import java.util.HashMap;

import ghidra.app.plugin.core.analysis.AnalysisState;
import ghidra.app.plugin.core.analysis.AnalysisStateInfo;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;

/**
 * Class for holding the {@link ClassFileJava} and {@link MethodInfoJava} in memory
 * for a particular .class file Program. These describe the objects in the constant pool and
 * signatures of individual methods.  They are parsed directly from the .class
 * file (and so can't really change) and are shared via this {@link AnalysisState} with
 * any plug-in that needs to do p-code analysis. 
 */
public class ClassFileAnalysisState implements AnalysisState {

	private Program program;
	private ClassFileJava classFile;					// Constant-pool and method descriptions
	private HashMap<Address, MethodInfoJava> methodMap;	// Map from address to method description

	public ClassFileAnalysisState(Program program) throws IOException {
		this.program = program;
		AddressFactory factory = program.getAddressFactory();
		AddressSpace space = factory.getAddressSpace("constantPool");
		if (space == null) {
			throw new IllegalStateException("Not a valid class file");
		}
		Memory memory = program.getMemory();
		MemoryByteProvider provider = new MemoryByteProvider(memory, space);
		BinaryReader reader = new BinaryReader(provider, false);
		classFile = new ClassFileJava(reader);
	}

	/**
	 * @return the class file information {@link ClassFileJava} held by this {@link AnalysisState}
	 */
	public ClassFileJava getClassFile() {
		return classFile;
	}

	/**
	 * Recover the description of the method at a specific address.
	 * @param addr is the given Address
	 * @return the MethodInfoJava describing the method, or null if no method is found at the address
	 */
	public MethodInfoJava getMethodInfo(Address addr) {
		synchronized (this) {
			if (methodMap == null) {
				try {
					buildMethodMap();
				}
				catch (MemoryAccessException e) {
					Msg.error(this, e.getMessage(), e);
					// methodMap will be non-null but empty
				}
			}
		}
		return methodMap.get(addr);
	}

	/**
	 * Walk through the {@link MethodInfoJava} objects in {@link ClassFileJava} and
	 * create a map from Address to the corresponding object
	 * @throws MemoryAccessException
	 */
	private void buildMethodMap() throws MemoryAccessException {
		methodMap = new HashMap<>();
		MethodInfoJava[] methods = classFile.getMethods();
		Memory memory = program.getMemory();
		AddressSpace defaultAddressSpace = program.getAddressFactory().getDefaultAddressSpace();
		for (int i = 0, max = methods.length; i < max; ++i) {
			Address methodIndexAddress = JavaClassUtil.toLookupAddress(program, i);
			int offset = memory.getInt(methodIndexAddress);
			Address methodStart = defaultAddressSpace.getAddress(offset);
			methodMap.put(methodStart, methods[i]);
		}
	}

	/**
	 * Return persistent <code>ClassFileAnalysisState</code> which corresponds to the specified program instance.
	 * @param program
	 * @return <code>ClassFileAnalysisState</code> for specified program instance
	 */
	public static synchronized ClassFileAnalysisState getState(Program program) throws IOException {
		ClassFileAnalysisState analysisState =
			AnalysisStateInfo.getAnalysisState(program, ClassFileAnalysisState.class);
		if (analysisState == null) {
			analysisState = new ClassFileAnalysisState(program);
			AnalysisStateInfo.putAnalysisState(program, analysisState);
		}
		return analysisState;
	}
}
