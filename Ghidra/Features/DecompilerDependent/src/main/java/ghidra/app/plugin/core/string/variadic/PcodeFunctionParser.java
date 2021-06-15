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
package ghidra.app.plugin.core.string.variadic;

import java.util.*;

import ghidra.docking.settings.SettingsImpl;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;

/**
 * Class for parsing functions' Pcode representations and finding variadic
 * functions being called
 *
 */
public class PcodeFunctionParser {

	// All values within the range [32, 126] are ascii readable
	private static final int READABLE_ASCII_LOWER_BOUND = 32;
	private static final int READABLE_ASCII_UPPER_BOUND = 126;
	// How many bytes to read from a memory address when initial format
	// String cannot be found. This normally only happens for short format
	// Strings with lengths less than 5
	private static final int BUFFER_LENGTH = 20;
	private static final String CALL_INSTRUCTION = "CALL";

	private Program program;

	public PcodeFunctionParser(Program program) {
		this.program = program;
	}

	/**
	 * Takes pcode ops of a function and parses them to determine whether there are
	 * any calls to variadic functions that use format Strings.
	 * 
	 * @param pcodeOps            List of PcodeOpAST for a function
	 * @param addressToCandidateData map of Addresses to format String data
	 * @param variadicFunctionNames   Set of variadic functions to look for
	 * @return List of variadic functions that the current function calls
	 */
	public List<FunctionCallData> parseFunctionForCallData(List<PcodeOpAST> pcodeOps,
			Map<Address, Data> addressToCandidateData, Set<String> variadicFunctionNames) {

		if (pcodeOps == null || addressToCandidateData == null || variadicFunctionNames == null ||
			this.program == null) {
			return null;
		}
		List<FunctionCallData> functionCallDataList = new ArrayList<>();
		for (PcodeOpAST ast : pcodeOps) {
			Varnode firstNode = ast.getInput(0);
			if (firstNode == null) {
				continue;
			}
			if (ast.getMnemonic().contentEquals(CALL_INSTRUCTION)) {

				FunctionManager functionManager = this.program.getFunctionManager();
				Function function = functionManager.getFunctionAt(firstNode.getAddress());
				if (function == null) {
					return null;
				}
				String functionName = function.getName();
				if (variadicFunctionNames.contains(functionName)) {
					Varnode[] inputs = ast.getInputs();
					if (inputs.length > 0) {
						boolean hasDefinedFormatString = searchForVariadicCallData(ast,
							addressToCandidateData, functionCallDataList, functionName);
						if (!hasDefinedFormatString) {
							searchForHiddenFormatStrings(ast, functionCallDataList, functionName);
						}
					}
				}
			}
		}
		return functionCallDataList;
	}

	private boolean searchForVariadicCallData(PcodeOpAST ast,
			Map<Address, Data> addressToCandidateData, List<FunctionCallData> functionCallDataList,
			String functionName) {

		boolean hasDefinedFormatString = false;
		Varnode[] inputs = ast.getInputs();
		for (int i = 1; i < inputs.length; i++) {
			Varnode v = inputs[i];
			Data data = null;
			Address ramSpaceAddress = convertAddressToRamSpace(v.getAddress());
			if (addressToCandidateData.containsKey(ramSpaceAddress)) {
				data = addressToCandidateData.get(ramSpaceAddress);
				functionCallDataList.add(new FunctionCallData(ast.getSeqnum().getTarget(),
					functionName, data.getDefaultValueRepresentation()));
				hasDefinedFormatString = true;
			}
		}
		return hasDefinedFormatString;
	}

	// If addrToCandidateData doesn't have format String data for this call
	// and we are calling a variadic function, parse the String to determine
	// whether it's a format String. 
	private void searchForHiddenFormatStrings(PcodeOpAST ast,
			List<FunctionCallData> functionCallDataList, String functionName) {

		Varnode[] inputs = ast.getInputs();
		// Initialize i = 1 to skip first input
		for (int i = 1; i < inputs.length; ++i) {
			Varnode v = inputs[i];
			String formatStringCandidate = findFormatString(v.getAddress());
			if (formatStringCandidate == null) {
				continue;
			}
			if (formatStringCandidate.contains("%")) {
				functionCallDataList.add(new FunctionCallData(ast.getSeqnum().getTarget(),
					functionName, formatStringCandidate));
			}
			break;
		}
	}

	private Address convertAddressToRamSpace(Address address) {

		String addressString = address.toString(false);
		return this.program.getAddressFactory().getAddress(addressString);
	}

	/**
	 * Looks at bytes at given address and converts to format String
	 * 
	 * @param address Address of format String
	 * @return format String
	 */
	private String findFormatString(Address address) {

		if (!address.getAddressSpace().isConstantSpace()) {
			return null;
		}

		// Old address associated with constant space which doesn't work
		Address ramSpaceAddress = convertAddressToRamSpace(address);

		MemoryBufferImpl memoryBuffer =
			new MemoryBufferImpl(this.program.getMemory(), ramSpaceAddress);
		SettingsImpl settings = new SettingsImpl();

		StringDataInstance stringDataInstance = StringDataInstance
				.getStringDataInstance(new StringDataType(), memoryBuffer, settings, BUFFER_LENGTH);
		String stringValue = stringDataInstance.getStringValue();
		if (stringValue == null) {
			return null;
		}

		String formatStringCandidate = "";
		for (int i = 0; i < stringValue.length(); i++) {
			if (!isAsciiReadable(stringValue.charAt(i))) {
				break;
			}
			formatStringCandidate += stringValue.charAt(i);
		}
		return formatStringCandidate;
	}

	private boolean isAsciiReadable(char c) {

		return c >= READABLE_ASCII_LOWER_BOUND && c <= READABLE_ASCII_UPPER_BOUND;
	}
}
