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
package ghidra.file.formats.android.dex.analyzer;

import java.io.IOException;
import java.util.List;
import java.util.TreeMap;

import ghidra.app.plugin.core.analysis.AnalysisState;
import ghidra.app.plugin.core.analysis.AnalysisStateInfo;
import ghidra.file.formats.android.dex.DexHeaderFactory;
import ghidra.file.formats.android.dex.format.*;
import ghidra.file.formats.android.dex.util.DexUtil;
import ghidra.framework.main.AppInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.util.SystemUtilities;

/**
 * This class is used to cache the {@link DexHeader} which holds constant pool and method information.
 * These do not change for a given .dex Program and can be shared (by this {@link AnalysisState})
 * between plug-ins that need to do analysis.
 */
final public class DexAnalysisState implements AnalysisState {

	private Program program;
	private DexHeader header;								// Collection of raw records parsed from .dex file
	private TreeMap<Address, EncodedMethod> methodMap;		// Cached map from Address -> EncodedMethod

	public DexAnalysisState(Program program, DexHeader header) {
		this.program = program;
		this.header = header;
	}

	/**
	 * Calculate the Address for every method in the list and add an entry to -methodMap-
	 * @param defaultAddressSpace is the AddressSpace all encoded offsets are relative to
	 * @param methodList is the list of encoded methods
	 */
	private void installMethodList(AddressSpace defaultAddressSpace,
			List<EncodedMethod> methodList) {
		for (EncodedMethod encodedMethod : methodList) {
			Address methodAddress = defaultAddressSpace
					.getAddress(DexUtil.METHOD_ADDRESS + encodedMethod.getCodeOffset());
			methodMap.put(methodAddress, encodedMethod);
		}
	}

	/**
	 * Calculate and cache a map from Address to the corresponding EncodedMethod object
	 * for all methods in the Program
	 */
	private void buildMethodMap() {
		methodMap = new TreeMap<>();
		AddressSpace defaultAddressSpace = program.getAddressFactory().getDefaultAddressSpace();
		for (ClassDefItem item : header.getClassDefs()) {

			ClassDataItem classDataItem = item.getClassDataItem();
			if (classDataItem == null) {
				continue;
			}
			installMethodList(defaultAddressSpace, classDataItem.getDirectMethods());
			installMethodList(defaultAddressSpace, classDataItem.getVirtualMethods());
		}
	}

	/**
	 * @return the {@link DexHeader} containing raw constant pool and method records
	 */
	public DexHeader getHeader() {
		return header;
	}

	/**
	 * Retrieve the EncodedMethod object, given its address
	 * @param addr is the Address of the method
	 * @return the EncodedMethod
	 */
	public EncodedMethod getEncodedMethod(Address addr) {
		synchronized (this) {
			if (methodMap == null) {
				buildMethodMap();

			}
		}
		return methodMap.get(addr);
	}

	/**
	 * Return persistent <code>DexAnalysisState</code> which corresponds to the specified program instance.
	 * @param program is the specified program instance
	 * @return <code>DexAnalysisState</code> for specified program instance
	 * @throws IOException if there are problems during construction of the state object
	 */
	public synchronized static DexAnalysisState getState(Program program) throws IOException {
		DexAnalysisState analysisState =
			AnalysisStateInfo.getAnalysisState(program, DexAnalysisState.class);
		if (analysisState == null) {
			DexHeader dexHeader = DexHeaderFactory.getDexHeader(program);
			analysisState = new DexAnalysisState(program, dexHeader);
			AnalysisStateInfo.putAnalysisState(program, analysisState);
		}
		return analysisState;
	}

	public static DexAnalysisState getState(Program program, Address address) throws IOException {
		DexAnalysisState analysisState =
			AnalysisStateInfo.getAnalysisState(program, DexAnalysisState.class);
		if (SystemUtilities.isInDevelopmentMode()) {
			analysisState = null; //always generate when in debug mode
		}
		if (analysisState == null) {
			DexHeader dexHeader = DexHeaderFactory.getDexHeader(program, address);
			analysisState = new DexAnalysisState(program, dexHeader);
			AnalysisStateInfo.putAnalysisState(program, analysisState);
		}
		return analysisState;
	}
}
