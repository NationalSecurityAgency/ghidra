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

import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;

/**
 * Class for parsing functions' Pcode representations and finding variadic
 * functions being called
 *
 */
public class PcodeFunctionParser {

	// How many bytes to read from a memory address when initial format
	// String cannot be found. This can happen when the format string
	// is too short or contains escape characters that thwart the
	// ASCII string analyzer
	private static final int NULL_TERMINATOR_PROBE = -1;

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
		for (PcodeOpAST callOp : pcodeOps) {
			if (callOp.getOpcode() != PcodeOp.CALL) {
				continue;
			}
			Varnode callTarget = callOp.getInput(0);
			if (callTarget == null) {
				continue;
			}
			FunctionManager functionManager = program.getFunctionManager();
			Function function = functionManager.getFunctionAt(callTarget.getAddress());
			if (function == null) {
				continue;
			}
			String functionName = function.getName();
			if (!variadicFunctionNames.contains(functionName)) {
				continue;
			}
			// <= since first input of callOp is call target and 
			// so not a function argument
			if (callOp.getNumInputs() <= function.getParameterCount()) {
				continue;
			}
			boolean hasDefinedFormatString = searchForVariadicCallData(callOp,
				addressToCandidateData, functionCallDataList, function);
			if (!hasDefinedFormatString) {
				searchForHiddenFormatStrings(callOp, functionCallDataList, function);
			}
		}
		return functionCallDataList;
	}

	private boolean searchForVariadicCallData(PcodeOpAST callOp,
			Map<Address, Data> addressToCandidateData, List<FunctionCallData> functionCallDataList,
			Function function) {
		//format string should be last parameter of Function ("..." doesn't count as a parameter)
		//don't subtract 1 since input 0 is the call target
		Varnode v = callOp.getInput(function.getParameterCount());
		Data data = null;
		Address ramSpaceAddress = convertAddressToRamSpace(v.getAddress());
		if (addressToCandidateData.containsKey(ramSpaceAddress)) {
			data = addressToCandidateData.get(ramSpaceAddress);
			functionCallDataList.add(new FunctionCallData(callOp.getSeqnum().getTarget(),
				function.getName(), data.getDefaultValueRepresentation()));
			return true;
		}
		//check for offcut references into a larger defined string
		Data containing = program.getListing().getDataContaining(ramSpaceAddress);
		if (containing == null) {
			return false;
		}
		if (addressToCandidateData.containsKey(containing.getAddress())) {
			StringDataInstance entire = StringDataInstance.getStringDataInstance(containing);
			String subString = entire
					.getByteOffcut(
						(int) (ramSpaceAddress.getOffset() - containing.getAddress().getOffset()))
					.getStringValue();
			if (subString != null) {
				functionCallDataList.add(new FunctionCallData(callOp.getSeqnum().getTarget(),
					function.getName(), subString));
				return true;
			}
		}
		return false;
	}

	// If addrToCandidateData doesn't have format String data for this call
	// and we are calling a variadic function, parse the String to determine
	// whether it's a format String. 
	private void searchForHiddenFormatStrings(PcodeOpAST callOp,
			List<FunctionCallData> functionCallDataList, Function function) {

		int formatStringSlot = function.getParameterCount() - 1;
		Parameter param = function.getParameter(formatStringSlot);
		if (param == null || param.getSource().equals(SourceType.DEFAULT)) {
			return;
		}
		DataType type = param.getDataType();
		if ((type == null) || !(type instanceof Pointer)) {
			return;
		}
		//+1 since first input of callOp is call target address
		String formatStringCandidate = findNullTerminatedString(
			callOp.getInput(formatStringSlot + 1).getAddress(), (Pointer) type);
		if (formatStringCandidate == null) {
			return;
		}
		if (formatStringCandidate.contains("%")) {
			functionCallDataList.add(new FunctionCallData(callOp.getSeqnum().getTarget(),
				function.getName(), formatStringCandidate));
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
	 * @param pointer Pointer "type" of string
	 * @return format String
	 */
	String findNullTerminatedString(Address address, Pointer pointer) {

		if (!address.getAddressSpace().isConstantSpace()) {
			return null;
		}

		// Old address associated with constant space which doesn't work
		Address ramSpaceAddress = convertAddressToRamSpace(address);

		MemoryBufferImpl memoryBuffer =
			new MemoryBufferImpl(this.program.getMemory(), ramSpaceAddress);

		DataType charType = pointer.getDataType();
		//StringDataInstace.getStringDataInstance checks that charType is appropriate
		//and returns StringDataInstace.NULL_INSTANCE if not
		StringDataInstance stringDataInstance = StringDataInstance.getStringDataInstance(charType,
			memoryBuffer, charType.getDefaultSettings(), NULL_TERMINATOR_PROBE);
		int detectedLength = stringDataInstance.getStringLength();
		if (detectedLength == -1) {
			return null;
		}
		stringDataInstance = new StringDataInstance(charType, charType.getDefaultSettings(),
			memoryBuffer, detectedLength, true);
		return stringDataInstance.getStringValue();
	}

}
