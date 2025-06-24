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

import ghidra.app.util.bin.format.dwarf.DWARFUtil;
import ghidra.app.util.bin.format.golang.rtti.GoRttiMapper;
import ghidra.app.util.bin.format.golang.structmapping.MarkupSession;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Utility class that fixes golang function parameter storage using each function's current
 * parameter list (formal info only) as starting information.
 * 
 * TODO: verify GoFuncData.argsize property against what we calculate here 
 */
public class GoFunctionFixup {

	private final Program program;
	private final Function func;
	private final GoParamStorageAllocator storageAllocator;
	private final FunctionSignature newSignature;
	private final String newCallingConv;
	private final DataTypeManager dtm;

	public GoFunctionFixup(Function func, GoVer goVersion) {
		this.program = func.getProgram();
		this.dtm = program.getDataTypeManager();
		this.func = func;
		this.storageAllocator = new GoParamStorageAllocator(program, goVersion);
		this.newSignature = func.getSignature();
		this.newCallingConv = null;

		if (GoRttiMapper.isAbi0Func(func.getEntryPoint(), program)) {
			// Some (typically lower level) functions in the binary will be marked with a 
			// symbol that ends in the string "abi0".  
			// Throw away all registers and force stack allocation for everything 
			storageAllocator.setAbi0Mode();
		}
	}

	public GoFunctionFixup(Function func, FunctionSignature newSignature, String newCallingConv,
			GoParamStorageAllocator storageAllocator) {
		this.program = func.getProgram();
		this.dtm = program.getDataTypeManager();
		this.func = func;
		this.storageAllocator = storageAllocator;
		this.newSignature = newSignature;
		this.newCallingConv = newCallingConv;
	}

	public static boolean isClosureContext(ParameterDefinition p) {
		// TODO: could also check the data type of the param to insure its a struct { F... }
		return GoConstants.GOLANG_CLOSURE_CONTEXT_NAME.equals(p.getName()) &&
			p.getDataType() instanceof Pointer;
	}

	public static boolean isClosureContext(Parameter p) {
		// TODO: could also check the data type of the param to insure its a struct { F... }
		return GoConstants.GOLANG_CLOSURE_CONTEXT_NAME.equals(p.getName()) &&
			p.getDataType() instanceof Pointer;
	}

	public void apply() throws DuplicateNameException, InvalidInputException {

		List<Integer> spillVars = new ArrayList<>();

		// for each parameter in the function's param list, calculate custom storage for it
		List<Parameter> newParams = new ArrayList<>();
		for (ParameterDefinition param : newSignature.getArguments()) {
			DataType dt = param.getDataType();
			ParameterImpl newParam = null;
			boolean isClosure =
				isClosureContext(param) && storageAllocator.getClosureContextRegister() != null;

			List<Register> regStorage = isClosure
					? List.of(storageAllocator.getClosureContextRegister())
					: storageAllocator.getRegistersFor(dt);
			if (regStorage != null && !regStorage.isEmpty()) {
				newParam =
					createParamWithCustomStorage(param.getName(), param.getDataType(), regStorage);
				if (!isClosure) {
					spillVars.add(param.getOrdinal());
				}
				if (dt instanceof Structure &&
					newParam.getVariableStorage().size() != dt.getLength()) {
					MarkupSession.logWarningAt(program, func.getEntryPoint(),
						"Known storage allocation problem: param %s register allocation for structs missing inter-field padding."
								.formatted(newParam.toString()));
				}
			}
			else {
				newParam = createParamWithStackStorage(param.getName(), param.getDataType());
			}
			newParams.add(newParam);
		}

		// prepare for calculating return result custom storage
		storageAllocator.alignStack();
		storageAllocator.resetRegAllocation();

		DataType returnDT = newSignature.getReturnType();
		List<LocalVariable> returnResultAliasVars = new ArrayList<>();
		ReturnParameterImpl returnParam = returnDT != null
				? updateReturn(returnResultAliasVars)
				: null;

		storageAllocator.alignStack();

		// Check if the func's current params / storage is same
		if (!isEquivStorage(newParams, returnParam)) {
			// modify the function's signature to match the new info.
			// First try just changing the callingconv.  If that doesn't produce the correct
			// storage, then resort to forcing the storage
			func.updateFunction(newCallingConv, returnParam, newParams,
				FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.IMPORTED);
			if (!isEquivStorage(newParams, returnParam)) {
				func.updateFunction(newCallingConv, returnParam, newParams,
					FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.IMPORTED);
			}
		}

		// Remove any old local vars that are in the callers stack instead of in the local stack area
		for (Variable localVar : func.getLocalVariables()) {
			if (localVar.isStackVariable() && !isInLocalVarStorageArea(localVar.getStackOffset())) {
				func.removeVariable(localVar);
			}
		}

		// For any parameters that were passed as registers, the golang caller pre-allocates
		// space on the stack for the parameter value to be used when the register is overwritten.
		// Ghidra decompilation results are improved if those storage locations are covered
		// by variables that we create artificially.
		for (int paramOrdinal : spillVars) {
			Parameter param = func.getParameter(paramOrdinal);
			DataType paramDT = param.getFormalDataType();
			long stackOffset = storageAllocator.getStackAllocation(paramDT);
			Varnode stackVarnode =
				new Varnode(program.getAddressFactory().getStackSpace().getAddress(stackOffset),
					paramDT.getLength());
			VariableStorage varStorage = new VariableStorage(program, List.of(stackVarnode));
			String paramName = param.getName();
			if (paramName == null) {
				paramName = SymbolUtilities.getDefaultParamName(paramOrdinal);
			}
			LocalVariableImpl localVar =
				new LocalVariableImpl(paramName + "_spill", 0, paramDT, varStorage, program);

			// TODO: needs more thought
			func.addLocalVariable(localVar, SourceType.IMPORTED);
		}

		for (LocalVariable returnResultAliasVar : returnResultAliasVars) {
			func.addLocalVariable(returnResultAliasVar, SourceType.IMPORTED);
		}

		if (newSignature.hasNoReturn()) {
			func.setNoReturn(true);
		}
	}

	private boolean isEquivStorage(List<Parameter> newParams, Parameter returnParam) {
		boolean equivStorage = newParams.size() == func.getParameterCount();
		for (int i = 0; equivStorage && i < newParams.size(); i++) {
			Parameter currentParam = func.getParameter(i);
			Parameter newParam = newParams.get(i);
			equivStorage = currentParam.getDataType().isEquivalent(newParam.getDataType()) &&
				currentParam.getVariableStorage().equals(newParam.getVariableStorage());
		}
		equivStorage = equivStorage && returnParam != null && func.getReturn() != null &&
			func.getReturn().getVariableStorage().equals(returnParam.getVariableStorage());

		return equivStorage;
	}

	/**
	 * Returns a Ghidra data type that represents a zero-length array, to be used as a replacement
	 * for a zero-length array parameter.
	 * 
	 * @param dt data type that will donate its name to the created empty array type
	 * @return {@link DataType} that represents a specific zero-length array type
	 */
	public static DataType makeEmptyArrayDataType(DataType dt) {
		StructureDataType struct = new StructureDataType(dt.getCategoryPath(),
			".empty_" + dt.getName(), 0, dt.getDataTypeManager());
		struct.setToDefaultPacking();
		return struct;
	}

	private ParameterImpl createParamWithCustomStorage(String name, DataType dt,
			List<Register> regStorage) throws InvalidInputException {
		List<Varnode> varnodes =
			DWARFUtil.convertRegisterListToVarnodeStorage(regStorage, dt.getLength());
		VariableStorage varStorage = new VariableStorage(program, varnodes.toArray(Varnode[]::new));
		ParameterImpl newParam = new ParameterImpl(name, Parameter.UNASSIGNED_ORDINAL, dt,
			varStorage, true, program, SourceType.IMPORTED);
		return newParam;
	}

	private ParameterImpl createParamWithStackStorage(String name, DataType dt)
			throws InvalidInputException {
		if (!DWARFUtil.isZeroByteDataType(dt)) {
			long stackOffset = storageAllocator.getStackAllocation(dt);
			return new ParameterImpl(name, dt, (int) stackOffset, program);
		}
		if (DWARFUtil.isEmptyArray(dt)) {
			dt = makeEmptyArrayDataType(dt);
		}
		Address zerobaseAddress = GoRttiMapper.getZerobaseAddress(program);
		return new ParameterImpl(name, dt, zerobaseAddress, program, SourceType.IMPORTED);

	}

	private ReturnParameterImpl updateReturn(List<LocalVariable> returnResultAliasVars)
			throws InvalidInputException {

		DataType returnDT = newSignature.getReturnType();
		List<Varnode> varnodes = new ArrayList<>();

		if (returnDT == null || Undefined.isUndefined(returnDT)) {
			return null;
		}
		if (DWARFUtil.isVoid(returnDT)) {
			return new ReturnParameterImpl(VoidDataType.dataType, VariableStorage.VOID_STORAGE,
				program);
		}

		GoFunctionMultiReturn multiReturn;
		if ((multiReturn =
			GoFunctionMultiReturn.fromStructure(returnDT, dtm, storageAllocator)) != null) {
			// allocate storage for individual elements of the struct because they were
			// originally separate return values.
			// Also turn off endianness fixups in the registers that are fetched
			// because we will do it manually
			returnDT = multiReturn.getStruct();

			for (DataTypeComponent dtc : multiReturn.getComponentsInOriginalOrder()) {
				allocateReturnStorage(dtc.getFieldName() + "_return_result_alias",
					dtc.getDataType(), varnodes, returnResultAliasVars, false);
			}

			if (!program.getMemory().isBigEndian()) {
				reverseNonStackStorageLocations(varnodes);
			}
		}
		else if (DWARFUtil.isZeroByteDataType(returnDT)) {
			if (DWARFUtil.isEmptyArray(returnDT)) {
				returnDT = makeEmptyArrayDataType(returnDT);
			}
			varnodes.add(new Varnode(GoRttiMapper.getZerobaseAddress(program), 1));
		}
		else {
			allocateReturnStorage("return_value_alias_variable", returnDT, varnodes,
				returnResultAliasVars, true);
		}

		if (varnodes.isEmpty()) {
			return null;
		}
		VariableStorage varStorage = new VariableStorage(program, varnodes.toArray(Varnode[]::new));
		return new ReturnParameterImpl(returnDT, varStorage, true, program);
	}

	private void allocateReturnStorage(String name_unused, DataType dt, List<Varnode> varnodes,
			List<LocalVariable> returnResultAliasVars, boolean allowEndianFixups)
			throws InvalidInputException {
		if (DWARFUtil.isZeroByteDataType(dt)) {
			return;
		}

		List<Register> regStorage = storageAllocator.getRegistersFor(dt, allowEndianFixups);
		if (regStorage != null && !regStorage.isEmpty()) {
			List<Varnode> nodes =
				DWARFUtil.convertRegisterListToVarnodeStorage(regStorage, dt.getLength());
			varnodes.addAll(nodes);
		}
		else {
			long stackOffset = storageAllocator.getStackAllocation(dt);
			// when the return value is on the stack, the decompiler's output is improved
			// when the function has something at the stack location
			LocalVariableImpl returnAliasLocalVar = new LocalVariableImpl(name_unused, dt,
				(int) stackOffset, program, SourceType.USER_DEFINED);
			returnResultAliasVars.add(returnAliasLocalVar);

			if (!varnodes.isEmpty()) {
				int prevIndex = storageAllocator.isBigEndian()
						? varnodes.size() - 1
						: 0;
				Varnode prev = varnodes.get(prevIndex);
				if (prev.getAddress().isStackAddress()) {
					// if ( prev.getAddress().getOffset() + prev.getSize() != stackOffset ) {
					//	throw new InvalidInputException("Non-adjacent stack storage");
					// }

					Varnode updatedVN =
						new Varnode(prev.getAddress(), prev.getSize() + dt.getLength());
					varnodes.set(prevIndex, updatedVN);
					return;
				}
				// fall thru and add a new varnode
			}
			varnodes.add(!storageAllocator.isBigEndian() ? 0 : varnodes.size(),
				new Varnode(program.getAddressFactory().getStackSpace().getAddress(stackOffset),
					dt.getLength()));
		}
	}

	private boolean isInLocalVarStorageArea(long stackOffset) {
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
	 * @param varnodes list of {@link Varnode varnodes} that will be modified in-place
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
