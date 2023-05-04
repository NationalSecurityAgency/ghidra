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
package ghidra.app.util.bin.format.golang;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.plugin.core.analysis.GolangSymbolAnalyzer;
import ghidra.app.util.bin.format.dwarf4.DWARFUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Utility class to fix Golang function parameter storage
 */
public class GoFunctionFixup {

	/**
	 * Assigns custom storage for a function's parameters, using the function's current
	 * parameter list (formal info only) as starting information.
	 *  
	 * @param func
	 * @throws DuplicateNameException
	 * @throws InvalidInputException
	 */
	public static void fixupFunction(Function func)
			throws DuplicateNameException, InvalidInputException {
		Program program = func.getProgram();
		GoVer goVersion = GoVer.fromProgramProperties(program);
		fixupFunction(func, goVersion);
	}

	public static void fixupFunction(Function func, GoVer goVersion)
			throws DuplicateNameException, InvalidInputException {
		Program program = func.getProgram();
		GoParamStorageAllocator storageAllocator = new GoParamStorageAllocator(program, goVersion);

		if (isGolangAbi0Func(func)) {
			// Some (typically lower level) functions in the binary will be marked with a 
			// symbol that ends in the string "abi0".  
			// Throw away all registers and force stack allocation for everything 
			storageAllocator.setAbi0Mode();
		}

		fixupFunction(func, storageAllocator);
	}

	private static void fixupFunction(Function func, GoParamStorageAllocator storageAllocator)
			throws DuplicateNameException, InvalidInputException {
		List<ParameterImpl> spillVars = new ArrayList<>();
		Program program = func.getProgram();

		// for each parameter in the function's param list, calculate custom storage for it
		List<ParameterImpl> newParams = new ArrayList<>();
		for (Parameter oldParam : func.getParameters()) {
			DataType dt = oldParam.getFormalDataType();
			ParameterImpl newParam = null;
			List<Register> regStorage = storageAllocator.getRegistersFor(dt);
			if (regStorage != null && !regStorage.isEmpty()) {
				newParam = updateParamWithCustomRegisterStorage(oldParam, regStorage);
				spillVars.add(newParam);
				if (dt instanceof Structure &&
					newParam.getVariableStorage().size() != dt.getLength()) {
					Msg.warn(GoFunctionFixup.class,
						"Known storage allocation problem: func %s@%s param %s register allocation for structs missing inter-field padding."
								.formatted(func.getName(), func.getEntryPoint(),
									newParam.toString()));
				}
			}
			else {
				newParam = updateParamWithStackStorage(oldParam, storageAllocator);
			}
			newParams.add(newParam);
		}

		// prepare for calculating return result custom storage
		storageAllocator.alignStack();
		storageAllocator.resetRegAllocation();

		DataType returnDT = func.getReturnType();
		List<LocalVariable> returnResultAliasVars = new ArrayList<>();
		ReturnParameterImpl returnParam = returnDT != null
				? updateReturn(func, storageAllocator, returnResultAliasVars)
				: null;

		storageAllocator.alignStack();

		if (returnParam == null && newParams.isEmpty()) {
			// its better to do nothing than lock the signature down
			return;
		}

		// Update the function in Ghidra
		func.updateFunction(null, returnParam, newParams, FunctionUpdateType.CUSTOM_STORAGE, true,
			SourceType.USER_DEFINED);

		// Remove any old local vars that are in the callers stack instead of in the local stack area
		for (Variable localVar : func.getLocalVariables()) {
			if (localVar.isStackVariable() &&
				!isInLocalVarStorageArea(func, localVar.getStackOffset())) {
				func.removeVariable(localVar);
			}
		}

		// For any parameters that were passed as registers, the golang caller pre-allocates
		// space on the stack for the parameter value to be used when the register is overwritten.
		// Ghidra decompilation results are improved if those storage locations are covered
		// by variables that we create artificially.
		for (ParameterImpl param : spillVars) {
			DataType paramDT = param.getFormalDataType();
			long stackOffset = storageAllocator.getStackAllocation(paramDT);
			Varnode stackVarnode =
				new Varnode(program.getAddressFactory().getStackSpace().getAddress(stackOffset),
					paramDT.getLength());
			VariableStorage varStorage = new VariableStorage(program, List.of(stackVarnode));
			LocalVariableImpl localVar =
				new LocalVariableImpl(param.getName() + "-spill", 0, paramDT, varStorage, program);

			// TODO: needs more thought
			func.addLocalVariable(localVar, SourceType.USER_DEFINED);
		}

		for (LocalVariable returnResultAliasVar : returnResultAliasVars) {
			func.addLocalVariable(returnResultAliasVar, SourceType.USER_DEFINED);
		}
	}

	/**
	 * Returns a Ghidra data type that represents a zero-length array, to be used as a replacement
	 * for a zero-length array parameter.
	 * 
	 * @param dt
	 * @return
	 */
	public static DataType makeEmptyArrayDataType(DataType dt) {
		StructureDataType struct = new StructureDataType(dt.getCategoryPath(),
			"empty_" + dt.getName(), 0, dt.getDataTypeManager());
		struct.setToDefaultPacking();
		return struct;
	}

	private static ParameterImpl updateParamWithCustomRegisterStorage(Parameter oldParam,
			List<Register> regStorage) throws InvalidInputException {
		Program program = oldParam.getProgram();
		DataType dt = oldParam.getDataType();
		List<Varnode> varnodes =
			DWARFUtil.convertRegisterListToVarnodeStorage(regStorage, dt.getLength());
		VariableStorage varStorage =
			new VariableStorage(program, varnodes.toArray(Varnode[]::new));
		ParameterImpl newParam =
			new ParameterImpl(oldParam.getName(), Parameter.UNASSIGNED_ORDINAL, dt,
				varStorage, true, program, SourceType.USER_DEFINED);
		return newParam;
	}

	private static ParameterImpl updateParamWithStackStorage(Parameter oldParam,
			GoParamStorageAllocator storageAllocator) throws InvalidInputException {
		DataType dt = oldParam.getDataType();
		Program program = oldParam.getProgram();
		if (!DWARFUtil.isZeroByteDataType(dt)) {
			long stackOffset = storageAllocator.getStackAllocation(dt);
			return new ParameterImpl(oldParam.getName(), dt, (int) stackOffset, program);
		}
		else {
			if (DWARFUtil.isEmptyArray(dt)) {
				dt = makeEmptyArrayDataType(dt);
			}
			Address zerobaseAddress = GolangSymbolAnalyzer.getZerobaseAddress(program);
			return new ParameterImpl(oldParam.getName(), dt, zerobaseAddress, program,
				SourceType.USER_DEFINED);
		}

	}

	private static ReturnParameterImpl updateReturn(Function func,
			GoParamStorageAllocator storageAllocator, List<LocalVariable> returnResultAliasVars)
			throws InvalidInputException {

		Program program = func.getProgram();
		DataTypeManager dtm = program.getDataTypeManager();
		DataType returnDT = func.getReturnType();
		List<Varnode> varnodes = new ArrayList<>();

		if (returnDT == null || Undefined.isUndefined(returnDT) || DWARFUtil.isVoid(returnDT)) {
			return null;
		}

//		status refactoring return result storage calc to use new GoFunctionMultiReturn
//		class to embed ordinal order in data type so that original data type and calc info
//		can be recreated.
		
		GoFunctionMultiReturn multiReturn;
		if ((multiReturn =
			GoFunctionMultiReturn.fromStructure(returnDT, dtm, storageAllocator)) != null) {
			// allocate storage for individual elements of the struct because they were
			// originally separate return values.
			// Also turn off endianness fixups in the registers that are fetched
			// because we will do it manually
			returnDT = multiReturn.getStruct();

			for (DataTypeComponent dtc : multiReturn.getNormalStorageComponents()) {
				allocateReturnStorage(program, dtc.getFieldName() + "-return-result-alias",
					dtc.getDataType(), storageAllocator, varnodes, returnResultAliasVars,
					false);
			}
			for (DataTypeComponent dtc : multiReturn.getStackStorageComponents()) {
				allocateReturnStorage(program, dtc.getFieldName() + "-return-result-alias",
					dtc.getDataType(), storageAllocator, varnodes, returnResultAliasVars,
					false);
			}
			if (!program.getMemory().isBigEndian()) {
				reverseNonStackStorageLocations(varnodes);
			}
		}
		else if (DWARFUtil.isZeroByteDataType(returnDT)) {
			if (DWARFUtil.isEmptyArray(returnDT)) {
				returnDT = makeEmptyArrayDataType(returnDT);
			}
			varnodes.add(new Varnode(GolangSymbolAnalyzer.getZerobaseAddress(program), 1));
		}
		else {
			allocateReturnStorage(program, "return-value-alias-variable", returnDT,
				storageAllocator, varnodes, returnResultAliasVars, true);
		}

		if (varnodes.isEmpty()) {
			return null;
		}
		VariableStorage varStorage =
			new VariableStorage(program, varnodes.toArray(Varnode[]::new));
		return new ReturnParameterImpl(returnDT, varStorage, true, program);
	}

	private static void allocateReturnStorage(Program program, String name_unused, DataType dt,
			GoParamStorageAllocator storageAllocator, List<Varnode> varnodes,
			List<LocalVariable> returnResultAliasVars, boolean allowEndianFixups)
			throws InvalidInputException {
		List<Register> regStorage = storageAllocator.getRegistersFor(dt, allowEndianFixups);
		if (regStorage != null && !regStorage.isEmpty()) {
			varnodes.addAll(
				DWARFUtil.convertRegisterListToVarnodeStorage(regStorage, dt.getLength()));
		}
		else {
			if (!DWARFUtil.isZeroByteDataType(dt)) {
				long stackOffset = storageAllocator.getStackAllocation(dt);
				varnodes.add(
					new Varnode(program.getAddressFactory().getStackSpace().getAddress(stackOffset),
						dt.getLength()));

				// when the return value is on the stack, the decompiler's output is improved
				// when the function has something at the stack location
				LocalVariableImpl returnAliasLocalVar = new LocalVariableImpl(name_unused, dt,
					(int) stackOffset, program, SourceType.USER_DEFINED);
				returnResultAliasVars.add(returnAliasLocalVar);
			}
		}
	}

	public static boolean isGolangAbi0Func(Function func) {
		Address funcAddr = func.getEntryPoint();
		for (Symbol symbol : func.getProgram().getSymbolTable().getSymbolsAsIterator(funcAddr)) {
			if (symbol.getSymbolType() == SymbolType.LABEL) {
				String labelName = symbol.getName();
				if (labelName.endsWith("abi0")) {
					return true;
				}
			}
		}
		return false;
	}

	public static boolean isInLocalVarStorageArea(Function func, long stackOffset) {
		Program program = func.getProgram();
		boolean paramsHavePositiveOffset = program.getCompilerSpec().stackGrowsNegative();
		return (paramsHavePositiveOffset && stackOffset < 0) ||
			(!paramsHavePositiveOffset && stackOffset >= 0);
	}

	/**
	 * Invert the order of the any register storage locations to match the decompiler's logic
	 * for assigning storage to structs that varies on endianness.
	 * <p>
	 * Only valid for storage scheme that has all register storages listed first / contiguous.
	 * 
	 * @param varnodes
	 */
	public static void reverseNonStackStorageLocations(List<Varnode> varnodes) {
		int regStorageCount;
		for (regStorageCount = 0; regStorageCount < varnodes.size(); regStorageCount++) {
			if (DWARFUtil.isStackVarnode(varnodes.get(regStorageCount))) {
				break;
			}
		}
		List<Varnode> regStorageList = new ArrayList<>(varnodes.subList(0, regStorageCount));
		for (int i = 0; i < regStorageList.size(); i++) {
			varnodes.set(i, regStorageList.get(regStorageList.size() - 1 - i));
		}

	}
}
