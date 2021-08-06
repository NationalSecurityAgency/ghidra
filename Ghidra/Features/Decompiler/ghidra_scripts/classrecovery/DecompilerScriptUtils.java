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
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class DecompilerScriptUtils {

	private Program program;
	private PluginTool tool;
	private TaskMonitor monitor;

	private DecompInterface decompInterface;

	DecompilerScriptUtils(Program program, PluginTool tool, TaskMonitor monitor) {
		this.program = program;
		this.monitor = monitor;
		this.tool = tool;

		decompInterface = setupDecompilerInterface();
	}

	/**
	 * Method to setup the decompiler interface for the given program
	 * @return the interface to the decompiler
	 */
	public DecompInterface setupDecompilerInterface() {

		decompInterface = new DecompInterface();

		DecompileOptions options;
		options = new DecompileOptions();
		OptionsService service = tool.getService(OptionsService.class);
		if (service != null) {
			ToolOptions opt = service.getOptions("Decompiler");
			options.grabFromToolAndProgram(null, opt, program);
		}
		decompInterface.setOptions(options);

		decompInterface.toggleCCode(true);
		decompInterface.toggleSyntaxTree(true);
		decompInterface.setSimplificationStyle("decompile");

		if (!decompInterface.openProgram(program)) {
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
				monitor.checkCanceled();
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

	public Address getAssignedAddressFromPcode(Varnode storedValue) {

		long addressOffset;
		if (storedValue.isConstant()) {
			addressOffset = storedValue.getOffset();
			Address possibleAddress = toAddr(addressOffset);
			if (possibleAddress == null || !program.getMemory().contains(possibleAddress)) {
				return null;
			}
			return possibleAddress;
		}

		PcodeOp valuePcodeOp = storedValue.getDef();

		if (valuePcodeOp == null) {
			return null;
		}

		if (valuePcodeOp.getOpcode() == PcodeOp.CAST || valuePcodeOp.getOpcode() == PcodeOp.COPY) {

			Varnode constantVarnode = valuePcodeOp.getInput(0);
			return getAssignedAddressFromPcode(constantVarnode);

		}
		else if (valuePcodeOp.getOpcode() != PcodeOp.PTRSUB) {
			return null;
		}

		// don't need to check isConst bc always is
		Varnode constantVarnode = valuePcodeOp.getInput(1);
		addressOffset = constantVarnode.getOffset();
		Address possibleAddress = toAddr(addressOffset);
		if (possibleAddress == null || !program.getMemory().contains(possibleAddress)) {
			return null;
		}
		return possibleAddress;
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
	 * Returns a new address with the specified offset in the default address space.
	 * @param offset the offset for the new address
	 * @return a new address with the specified offset in the default address space
	 */
	public final Address toAddr(long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

}
