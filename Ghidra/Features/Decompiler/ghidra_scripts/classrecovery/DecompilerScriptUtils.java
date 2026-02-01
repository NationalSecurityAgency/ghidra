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

import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class DecompilerScriptUtils {

	private Program program;
	private ServiceProvider serviceProvider;
	private TaskMonitor monitor;

	private DecompInterface decompInterface;

	DecompilerScriptUtils(Program program, ServiceProvider serviceProvider, TaskMonitor monitor) {
		this.program = program;
		this.monitor = monitor;
		this.serviceProvider = serviceProvider;

		decompInterface = setupDecompilerInterface();
	}

	/**
	 * Method to setup the decompiler interface for the given program
	 * @return the interface to the decompiler or null if failed to open program
	 */
	public DecompInterface setupDecompilerInterface() {

		decompInterface = new DecompInterface();

		DecompileOptions options = DecompilerUtils.getDecompileOptions(serviceProvider, program);

		decompInterface.setOptions(options);

		decompInterface.toggleCCode(true);
		decompInterface.toggleSyntaxTree(true);
		decompInterface.setSimplificationStyle("decompile");

		if (!decompInterface.openProgram(program)) {
			decompInterface.dispose();
			return null;
		}
		return decompInterface;

	}

	public DecompInterface getDecompilerInterface() {
		return decompInterface;
	}

	/**
	 * Method to decompile the given function and return the function's HighFunction
	 * @param function the given function
	 * @return the HighFunction for the given function or null if there are issues decompiling the function
	 */
	public HighFunction getHighFunction(Function function) {

		DecompileResults res = decompInterface.decompileFunction(function,
			decompInterface.getOptions().getDefaultTimeout(), null);

		decompInterface.flushCache();
		return res.getHighFunction();
	}

	/**
	 * Method to get the decompiler version of the given function's return type (which is not always 
	 * the same as the listing version)
	 * @param function the given function
	 * @return the decompiler version of the given function's return type (which is not always the 
	 * same as the listing version)
	 */
	public DataType getDecompilerReturnType(Function function) {

		DecompileResults decompRes = decompInterface.decompileFunction(function,
			decompInterface.getOptions().getDefaultTimeout(), monitor);

		//If can't decompile, return null
		if (decompRes == null || decompRes.getHighFunction() == null ||
			decompRes.getHighFunction().getFunctionPrototype() == null) {
			return null;
		}

		return decompRes.getHighFunction().getFunctionPrototype().getReturnType();
	}

	public void commitFunction(Function function) {
		DecompileResults decompRes = decompInterface.decompileFunction(function,
			decompInterface.getOptions().getDefaultTimeout(), monitor);

		if (decompRes == null || decompRes.getHighFunction() == null ||
			decompRes.getHighFunction().getFunctionPrototype() == null) {
			Msg.debug(this, "Couldn't commit params - null high function " +
				function.getEntryPoint().toString());
			return;
		}

		try {
			HighFunctionDBUtil.commitParamsToDatabase(decompRes.getHighFunction(), true,
				ReturnCommitOption.COMMIT, SourceType.ANALYSIS);
		}
		catch (DuplicateNameException e) {
			Msg.debug(this,
				"Couldn't commit params for " + function.getEntryPoint().toString() + " " + e);
			return;
		}
		catch (InvalidInputException e) {
			Msg.debug(this,
				"Couldn't commit params for " + function.getEntryPoint().toString() + " " + e);
			return;
		}
	}

	/**
	 * Method to retrieve the function signature string from the decompiler function prototype. NOTE:
	 * if there is a this param, it will not be included.
	 * @param function the given function
	 * @param includeReturn if true, include the return type in the signature string
	 * @return the function signature string
	 * @throws CancelledException if cancelled
	 */
	public String getFunctionSignatureString(Function function, boolean includeReturn)
			throws CancelledException {

		if (function == null) {
			return null;
		}

		StringBuffer stringBuffer = new StringBuffer();

		DecompileResults decompRes = decompInterface.decompileFunction(function,
			decompInterface.getOptions().getDefaultTimeout(), monitor);

		//If can't decompile, show the listing version of the function signature
		if (decompRes == null || decompRes.getHighFunction() == null ||
			decompRes.getHighFunction().getFunctionPrototype() == null) {
			return null;
		}

		HighFunction highFunction = decompRes.getHighFunction();

		FunctionPrototype functionPrototype = highFunction.getFunctionPrototype();

		if (includeReturn) {
			stringBuffer.append(functionPrototype.getReturnType().getDisplayName() + " ");
		}

		stringBuffer.append(function.getName() + "(");
		ParameterDefinition[] parameterDefinitions = functionPrototype.getParameterDefinitions();

		if (parameterDefinitions == null) {
			stringBuffer.append(");");
		}
		else {
			int paramCount = parameterDefinitions.length;
			for (int i = 0; i < parameterDefinitions.length; i++) {
				monitor.checkCancelled();
				ParameterDefinition param = parameterDefinitions[i];

				if (param.getName().equals("this")) {
					continue;
				}

				stringBuffer.append(param.getDataType().getDisplayName() + " " + param.getName());

				if (i == paramCount) {
					stringBuffer.append(");");
				}
				else {
					stringBuffer.append(", ");
				}
			}
		}

		return stringBuffer.toString();
	}

	/**
	 * Get the parameters from the decompiler for the given function
	 * @param function the given function
	 * @return the decompiler parameters for the given function
	 */
	public ParameterDefinition[] getParametersFromDecompiler(Function function) {

		DecompileResults decompRes = decompInterface.decompileFunction(function,
			decompInterface.getOptions().getDefaultTimeout(), monitor);

		if (decompRes == null || decompRes.getHighFunction() == null) {
			return null;
		}

		return decompRes.getHighFunction().getFunctionPrototype().getParameterDefinitions();
	}

	/**
	 * Method to dispose the decompiler interface
	 */
	public void disposeDecompilerInterface() {
		decompInterface.closeProgram();
		decompInterface.dispose();
	}

	/**
	 * Best-effort extraction of an address candidate from decompiler p-code.
	 * Returns {@code null} if the candidate is invalid or not mapped in program memory.
	 * @param storedValue the Varnode containing possible address
	 * @return the Address assigned to the Varnode, or null if invalid or not in program memory
	 */
	public Address getAssignedAddressFromPcode(Varnode storedValue) {

		if (storedValue.isConstant()) {
			return toAddr(storedValue.getOffset());
		}

		PcodeOp op = storedValue.getDef();
		if (op == null) {
			return null;
		}

		int opcode = op.getOpcode();
		if (opcode == PcodeOp.CAST || opcode == PcodeOp.COPY) {
			return getAssignedAddressFromPcode(op.getInput(0));
		}

		if (opcode != PcodeOp.PTRSUB) {
			return null;
		}

		// PTRSUB input(1) is always a constant offset (but may not represent a valid program address)
		return toAddr(op.getInput(1).getOffset());
	}

	/**
	 * Method to get the called address from the given CALL pcodeOp's input Varnode 
	 * @param pcodeOpInput the Varnode from a CALL pcodeOp input
	 * @return the calledAddress
	 */
	public Address getCalledAddressFromCallingPcodeOp(Varnode pcodeOpInput) {

		PcodeOp def = pcodeOpInput.getDef();
		if (def == null) {
			return null;
		}

		Varnode defInput = def.getInput(1);
		if (defInput == null) {
			return null;
		}

		Address defInputAddress = defInput.getAddress();
		if (defInputAddress == null) {
			return null;
		}

		long offset = defInputAddress.getOffset();

		Address calledAddress = program.getMinAddress().getNewAddress(offset);

		return calledAddress;
	}

	/**
	 * Attempts to convert the given offset to an {@link Address} in the default address space.
	 * <p>
	 * Decompiler pcode may surface non-pointer constants that heuristics attempt to interpret
	 * as addresses; this method performs a best-effort conversion and safely ignores
	 * invalid or unmapped candidates.
	 * <p>
	 *
	 * @param offset the offset to convert
	 * @return the address for the given offset, or {@code null} if the offset cannot be represented
	 *         as a valid address in the program's memory
	 */
	public final Address toAddr(long offset) {
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		try {
			Address addr = space.getAddress(offset);
			return program.getMemory().contains(addr) ? addr : null;
		}
		catch (AddressOutOfBoundsException e) {
			return null;
		}
	}

}
