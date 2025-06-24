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

import java.util.*;

import ghidra.app.util.bin.format.dwarf.*;
import ghidra.app.util.bin.format.dwarf.DWARFFunction.CommitMode;
import ghidra.app.util.bin.format.dwarf.funcfixup.DWARFFunctionFixup;
import ghidra.app.util.bin.format.golang.rtti.GoFuncData;
import ghidra.app.util.bin.format.golang.rtti.GoRttiMapper;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.classfinder.ExtensionPointProperties;
import ghidra.util.task.TaskMonitor;

/**
 * Fixups for golang functions found during DWARF processing.
 * <p>
 * Fixes storage of parameters to match the go callspec and modifies parameter lists to match
 * Ghidra's capabilities.
 * <p>
 * Special characters used by golang in symbol names (middle dot \u00B7, weird slash \u2215) are 
 * fixed up in DWARFProgram.getDWARFNameInfo() by calling 
 * GoSymbolName.fixGolangSpecialSymbolnameChars().
 * <p>
 * Go's 'unique' usage of DW_TAG_subroutine_type to define its ptr-to-ptr-to-func is handled in
 * DWARFDataTypeImporter.makeDataTypeForFunctionDefinition().
 */
@ExtensionPointProperties(priority = DWARFFunctionFixup.PRIORITY_NORMAL_EARLY)
public class GolangDWARFFunctionFixup implements DWARFFunctionFixup {

	public static final CategoryPath GOLANG_API_EXPORT =
		new CategoryPath(CategoryPath.ROOT, "GolangAPIExport");
	private static final String GOLANG_FUNC_INFO_PREFIX = "Golang function info: ";

	/**
	 * Returns true if the specified {@link DWARFFunction} wrapper refers to a function in a golang
	 * compile unit.
	 * 
	 * @param dfunc {@link DWARFFunction}
	 * @return boolean true or false
	 */
	public static boolean isGolangFunction(DWARFFunction dfunc) {
		DIEAggregate diea = dfunc.diea;
		int cuLang = diea.getCompilationUnit().getLanguage();
		if (cuLang != DWARFSourceLanguage.DW_LANG_Go) {
			return false;
		}
		// sanity check: gofuncs always have a void return type in dwarf
		if (!dfunc.retval.isVoidType()) {
			return false;
		}
		return true;
	}

	private GoRttiMapper goBinary;

	@Override
	public void fixupDWARFFunction(DWARFFunction dfunc) throws DWARFException {
		if (!isGolangFunction(dfunc) || !initGoBinaryContext(dfunc, TaskMonitor.DUMMY)) {
			return;
		}

		GoFuncData funcData = goBinary.getFunctionData(dfunc.address);
		if (funcData == null) {
			appendComment(dfunc.function, GOLANG_FUNC_INFO_PREFIX, "No function data");
			dfunc.signatureCommitMode = CommitMode.SKIP;
			return;
		}
		if (!funcData.getFlags().isEmpty()) {
			// Don't apply any DWARF info to special functions (ASM) as they are typically
			// marked as no-params, but in reality they do have params passed in a non-standard way.
			dfunc.signatureCommitMode = CommitMode.SKIP;
			return;
		}

		DataTypeManager dtm = goBinary.getProgram().getDataTypeManager();
		GoParamStorageAllocator storageAllocator = goBinary.newStorageAllocator();

		if (goBinary.isGolangAbi0Func(dfunc.function)) {
			// Some (typically lower level) functions in the binary will be marked with a 
			// symbol that ends in the string "abi0".  
			// Throw away all registers and force stack allocation for everything 
			storageAllocator.setAbi0Mode();
		}

		dfunc.callingConventionName =
			storageAllocator.isAbi0Mode() ? GoConstants.GOLANG_ABI0_CALLINGCONVENTION_NAME
					: GoConstants.GOLANG_ABI_INTERNAL_CALLINGCONVENTION_NAME;

		GoFunctionMultiReturn multiReturnInfo = fixupFormalFuncDef(dfunc, storageAllocator, dtm);
		fixupCustomStorage(dfunc, storageAllocator, dtm, multiReturnInfo);
	}

	private GoFunctionMultiReturn fixupFormalFuncDef(DWARFFunction dfunc,
			GoParamStorageAllocator storageAllocator, DataTypeManager dtm) {
		// Go funcs can have multiple return values, which are marked up in dwarf as parameters with
		// a special boolean flag.  Unnamed return values typically have a "~r0", "~r1", etc name
		// auto-assigned.
		// Pull them out of the param list and create a structure to hold them as the return value
		// They also need to be sorted so that stack storage items appear last, after register items.
		// Note: sometimes Go will duplicate the dwarf information about return values, which
		// will lead to have multiple "~r0", "~r1" elements.  These need to be de-duped.
		List<DWARFVariable> realParams = new ArrayList<>();
		List<DWARFVariable> returnParams = new ArrayList<>();
		Set<String> returnParamNames = new HashSet<>();
		for (DWARFVariable dvar : dfunc.params) {
			if (dvar.isOutputParameter) {
				if (returnParamNames.contains(dvar.name.getName())) {
					// skip this, its probably a duplicate.  Golang github issue #61357
					continue;
				}
				returnParamNames.add(dvar.name.getName());

				returnParams.add(dvar);
			}
			else {
				realParams.add(dvar);
			}
		}

		DataType returnType = VoidDataType.dataType;
		GoFunctionMultiReturn multiReturn = null;
		if (returnParams.size() == 1) {
			returnType = returnParams.get(0).type;
		}
		else if (returnParams.size() > 1) {
			multiReturn = new GoFunctionMultiReturn(GoConstants.GOLANG_CATEGORYPATH, returnParams,
				dfunc, dtm, storageAllocator);
			returnType = multiReturn.getStruct();
		}
		dfunc.retval = DWARFVariable.fromDataType(dfunc, returnType);
		dfunc.params = realParams;
		dfunc.varArg = false;	// golang varargs are implemented via slice parameter, so this is always false

		return multiReturn;
	}

	private void fixupCustomStorage(DWARFFunction dfunc, GoParamStorageAllocator storageAllocator,
			DataTypeManager dtm, GoFunctionMultiReturn multiReturn) {
		//
		// This method implements the pseudo-code in
		// https://github.com/golang/go/blob/master/src/cmd/compile/abi-internal.md.
		//

		// WARNING: this code should be kept in sync with GoFunctionFixup

		Program program = goBinary.getProgram();
		
		// Allocate custom storage for each parameter
		List<DWARFVariable> spillVars = new ArrayList<>();
		for (DWARFVariable dvar : dfunc.params) {
			List<Register> regStorage = storageAllocator.getRegistersFor(dvar.type);
			if (regStorage != null && !regStorage.isEmpty()) {
				dvar.setRegisterStorage(regStorage);
				spillVars.add(dvar);
				if (dvar.type instanceof Structure &&
					dvar.getStorageSize() != dvar.type.getLength()) {
					dfunc.getProgram()
							.logWarningAt(dfunc.address, dfunc.name.getName(),
								"Golang known storage allocation problem: param \"%s\" register allocation for structs missing inter-field padding."
										.formatted(dvar.name.getName()));
				}
			}
			else {
				if (!dvar.isZeroByte()) {
					long stackOffset = storageAllocator.getStackAllocation(dvar.type);
					dvar.setStackStorage(stackOffset);
				}
				else {
					if (dvar.isEmptyArray()) {
						dvar.type = GoFunctionFixup.makeEmptyArrayDataType(dvar.type);
					}
					Address zerobaseAddress = GoRttiMapper.getZerobaseAddress(program);
					dvar.setRamStorage(zerobaseAddress.getOffset());
				}
			}
		}
		storageAllocator.alignStack();
		storageAllocator.resetRegAllocation();

		// Allocate custom storage for the return value
		if (!dfunc.retval.isZeroByte()) {
			dfunc.retval.clearStorage();

			if (multiReturn != null) {
				// allocate storage for individual elements of the struct because they were
				// originally separate return values.
				// Also turn off endianness fixups in the registers that are fetched
				// because we will do it manually
				for (DataTypeComponent dtc : multiReturn.getComponentsInOriginalOrder()) {
					allocateReturnStorage(dfunc, dfunc.retval,
						dtc.getFieldName() + "_return_result_alias",
						dtc.getDataType(), storageAllocator, false);
				}

				if (!program.getMemory().isBigEndian()) {
					// Reverse the ordering of the storage varnodes when little-endian
					List<Varnode> varnodes = dfunc.retval.getVarnodes();
					GoFunctionFixup.reverseNonStackStorageLocations(varnodes);
					dfunc.retval.setVarnodes(varnodes);
				}
			}
			else {
				allocateReturnStorage(dfunc, dfunc.retval, "return_value_alias_variable",
					dfunc.retval.type, storageAllocator, true);
			}
		}
		else {
			if (dfunc.retval.isEmptyArray()) {
				dfunc.retval.type = GoFunctionFixup.makeEmptyArrayDataType(dfunc.retval.type);
			}
			if (!dfunc.retval.isVoidType()) {
				dfunc.retval.setRamStorage(GoRttiMapper.getZerobaseAddress(program).getOffset());
			}
		}
		storageAllocator.alignStack();

		// For any parameters that were passed as registers, the golang caller pre-allocates
		// space on the stack for the parameter value to be used when the register is overwritten.
		// Ghidra decompilation results are improved if those storage locations are covered
		// by variables that we create artificially.
		for (DWARFVariable dvar : spillVars) {
			DWARFVariable spill = DWARFVariable.fromDataType(dfunc, dvar.type);
			String paramName = dvar.name.getName() + "_spill";
			spill.name = dvar.name.replaceName(paramName, paramName);
			spill.setStackStorage(storageAllocator.getStackAllocation(spill.type));
			dfunc.localVars.add(spill);
		}

		// Override "localVarErrors" because we are pretty sure go's dwarf output is 
		// trustworthy now that we've over-written everything.
		// See SanityCheckDWARFFunctionFixup
		dfunc.localVarErrors = false;
		dfunc.signatureCommitMode = CommitMode.STORAGE;
	}

	private void allocateReturnStorage(DWARFFunction dfunc, DWARFVariable dvar, String name,
			DataType dt, GoParamStorageAllocator storageAllocator, boolean allowEndianFixups) {

		List<Register> regStorage = storageAllocator.getRegistersFor(dt, allowEndianFixups);
		if (regStorage != null && !regStorage.isEmpty()) {
			dvar.addRegisterStorage(regStorage);
		}
		else {
			if (!DWARFUtil.isZeroByteDataType(dt)) {
				long stackOffset = storageAllocator.getStackAllocation(dt);
				dvar.addStackStorage(stackOffset, dt.getLength());
				dfunc.localVars.add(createReturnResultAliasVar(dfunc, dt, name, stackOffset));
			}
		}
	}

	private DWARFVariable createReturnResultAliasVar(DWARFFunction dfunc, DataType dataType,
			String name, long stackOffset) {
		DWARFVariable returnResultVar = DWARFVariable.fromDataType(dfunc, dataType);
		returnResultVar.name = dfunc.name.createChild(name, name, SymbolType.LOCAL_VAR);
		returnResultVar.setStackStorage(stackOffset);
		return returnResultVar;
	}

	private boolean initGoBinaryContext(DWARFFunction dfunc, TaskMonitor monitor) {
		if (goBinary == null) {
			Program program = dfunc.getProgram().getGhidraProgram();
			goBinary = GoRttiMapper.getSharedGoBinary(program, monitor);
		}
		return goBinary != null;
	}

	private void appendComment(Function func, String prefix, String comment) {
		DWARFUtil.appendComment(goBinary.getProgram(), func.getEntryPoint(), CommentType.PLATE,
			prefix, comment, "\n");
	}
}
