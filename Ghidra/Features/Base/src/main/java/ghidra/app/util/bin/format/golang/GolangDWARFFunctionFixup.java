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
import ghidra.app.util.bin.format.dwarf4.DIEAggregate;
import ghidra.app.util.bin.format.dwarf4.DWARFUtil;
import ghidra.app.util.bin.format.dwarf4.encoding.DWARFSourceLanguage;
import ghidra.app.util.bin.format.dwarf4.funcfixup.DWARFFunctionFixup;
import ghidra.app.util.bin.format.dwarf4.next.*;
import ghidra.app.util.bin.format.dwarf4.next.DWARFFunction.CommitMode;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;
import ghidra.util.classfinder.ExtensionPointProperties;
import ghidra.util.exception.DuplicateNameException;

/**
 * Fixups for golang functions.
 * <p>
 * Fixes storage of parameters to match the go callspec and modifies parameter lists to match
 * Ghidra's capabilities.
 * <p>
 * Special characters used by golang in symbol names are fixed up in 
 * DWARFProgram.fixupSpecialMeaningCharacters():
 *   <li>"\u00B7" (middle dot) -> "."
 *   <li>"\u2215" (weird slash) -> "/"
 */
@ExtensionPointProperties(priority = DWARFFunctionFixup.PRIORITY_NORMAL_EARLY)
public class GolangDWARFFunctionFixup implements DWARFFunctionFixup {

	public static final CategoryPath GOLANG_API_EXPORT =
		new CategoryPath(CategoryPath.ROOT, "GolangAPIExport");

	public static boolean isGolangFunction(DWARFFunction dfunc) {
		DIEAggregate diea = dfunc.diea;
		int cuLang = diea.getCompilationUnit().getCompileUnit().getLanguage();
		if (cuLang != DWARFSourceLanguage.DW_LANG_Go) {
			return false;
		}
		// sanity check: gofuncs always have a void return type in dwarf
		if (!dfunc.retval.type.isEquivalent(VoidDataType.dataType)) {
			return false;
		}
		return true;
	}

	@Override
	public void fixupDWARFFunction(DWARFFunction dfunc, Function gfunc) {
		if (!isGolangFunction(dfunc)) {
			return;
		}
		GoVer goVersion = getGolangVersion(dfunc);
		if (goVersion == GoVer.UNKNOWN) {
			return;
		}

		DataTypeManager dtm = gfunc.getProgram().getDataTypeManager();
		GoParamStorageAllocator storageAllocator =
			new GoParamStorageAllocator(gfunc.getProgram(), goVersion);

		if (GoFunctionFixup.isGolangAbi0Func(gfunc)) {
			// Some (typically lower level) functions in the binary will be marked with a 
			// symbol that ends in the string "abi0".  
			// Throw away all registers and force stack allocation for everything 
			storageAllocator.setAbi0Mode();
			dfunc.prototypeModel = storageAllocator.getAbi0CallingConvention();
		}
		else {
			dfunc.prototypeModel = storageAllocator.getAbiInternalCallingConvention();
		}

		GoFunctionMultiReturn multiReturnInfo = fixupFormalFuncDef(dfunc, storageAllocator, dtm);
		fixupCustomStorage(dfunc, gfunc, storageAllocator, dtm, multiReturnInfo);
	}

	private GoFunctionMultiReturn fixupFormalFuncDef(DWARFFunction dfunc,
			GoParamStorageAllocator storageAllocator, DataTypeManager dtm) {
		// Go funcs can have multiple return values, which are marked up in dwarf as parameters with
		// a special boolean flag.  Unnamed return values typically have a "~r0", "~r1", etc name
		// auto-assigned.
		// Pull them out of the param list and create a structure to hold them as the return value
		// They also need to be sorted so that stack storage items appear last, after register items.
		List<DWARFVariable> realParams = new ArrayList<>();
		List<DWARFVariable> returnParams = new ArrayList<>();
		for (DWARFVariable dvar : dfunc.params) {
			if (dvar.isOutputParameter) {
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
			multiReturn = new GoFunctionMultiReturn(returnParams, dfunc, dtm, storageAllocator);
			returnType = multiReturn.getStruct();
		}
		dfunc.retval = DWARFVariable.fromDataType(dfunc, returnType);
		dfunc.params = realParams;
		dfunc.varArg = false;	// golang varargs are implemented via slice parameter, so this is always false

		return multiReturn;
	}

	private void fixupCustomStorage(DWARFFunction dfunc, Function gfunc,
			GoParamStorageAllocator storageAllocator, DataTypeManager dtm,
			GoFunctionMultiReturn multiReturn) {
		//
		// This method implements the pseudo-code in
		// https://github.com/golang/go/blob/master/src/cmd/compile/abi-internal.md.
		//

		// Allocate custom storage for each parameter
		List<DWARFVariable> spillVars = new ArrayList<>();
		for (DWARFVariable dvar : dfunc.params) {
			List<Register> regStorage = storageAllocator.getRegistersFor(dvar.type);
			if (regStorage != null && !regStorage.isEmpty()) {
				dvar.setRegisterStorage(regStorage);
				spillVars.add(dvar);
				if (dvar.type instanceof Structure &&
					dvar.getStorageSize() != dvar.type.getLength()) {
					Msg.warn(GoFunctionFixup.class,
						"Known storage allocation problem: func %s@%s param %s register allocation for structs missing inter-field padding."
								.formatted(dfunc.name.getName(), dfunc.address,
									dvar.name.getName()));
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
					Address zerobaseAddress = getZerobaseAddress(dfunc);
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
				for (DataTypeComponent dtc : multiReturn.getNormalStorageComponents()) {
					allocateReturnStorage(dfunc, dfunc.retval,
						dtc.getFieldName() + "-return-result-alias", dtc.getDataType(),
						storageAllocator, false);
				}

				// do items marked as "stack" last (because their order was modified to match
				// the decompiler's expectations for storage layout)
				for (DataTypeComponent dtc : multiReturn.getStackStorageComponents()) {
					allocateReturnStorage(dfunc, dfunc.retval,
						dtc.getFieldName() + "-return-result-alias", dtc.getDataType(),
						storageAllocator, false);
				}

				Program program = gfunc.getProgram();
				if (!program.getMemory().isBigEndian()) {
					// revserse the ordering of the storage varnodes when little-endian
					List<Varnode> varnodes = dfunc.retval.getVarnodes();
					GoFunctionFixup.reverseNonStackStorageLocations(varnodes);
					dfunc.retval.setVarnodes(varnodes);
				}
			}
			else {
				allocateReturnStorage(dfunc, dfunc.retval, "return-value-alias-variable",
					dfunc.retval.type, storageAllocator, true);
			}
		}
		else {
			if (dfunc.retval.isEmptyArray()) {
				dfunc.retval.type = GoFunctionFixup.makeEmptyArrayDataType(dfunc.retval.type);
			}
			if (!dfunc.retval.isVoidType()) {
				dfunc.retval.setRamStorage(getZerobaseAddress(dfunc).getOffset());
			}
		}
		storageAllocator.alignStack();

		// For any parameters that were passed as registers, the golang caller pre-allocates
		// space on the stack for the parameter value to be used when the register is overwritten.
		// Ghidra decompilation results are improved if those storage locations are covered
		// by variables that we create artificially.
		for (DWARFVariable dvar : spillVars) {
			DWARFVariable spill = DWARFVariable.fromDataType(dfunc, dvar.type);
			String paramName = dvar.name.getName() + "-spill";
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
		DWARFVariable returnResultVar =
			DWARFVariable.fromDataType(dfunc, dataType);
		returnResultVar.name = dfunc.name.createChild(name, name, SymbolType.LOCAL_VAR);
		returnResultVar.setStackStorage(stackOffset);
		return returnResultVar;
	}

//	/**
//	 * Create a structure that holds the multiple return values from a golang func.
//	 * <p>
//	 * The contents of the structure may not be in the same order as the formal declaration,
//	 * but instead are ordered to make custom varnode storage work.
//	 * <p>
//	 * Because stack varnodes must be placed in a certain order of storage, items that are
//	 * stack based are tagged with a text comment "stack" to allow storage to be correctly 
//	 * recalculated later.
//	 *   
//	 * @param returnParams
//	 * @param dfunc
//	 * @param dtm
//	 * @param storageAllocator
//	 * @return
//	 */
//	public static Structure createStructForReturnValues(List<DWARFVariable> returnParams,
//			DWARFFunction dfunc, DataTypeManager dtm,
//			GoParamStorageAllocator storageAllocator) {
//
//		String returnStructName = dfunc.name.getName() + MULTIVALUE_RETURNTYPE_SUFFIX;
//		DWARFNameInfo structDNI = dfunc.name.replaceName(returnStructName, returnStructName);
//		Structure struct =
//			new StructureDataType(structDNI.getParentCP(), structDNI.getName(), 0, dtm);
//		struct.setPackingEnabled(true);
//		struct.setExplicitPackingValue(1);
//
//		storageAllocator = storageAllocator.clone();
//		List<DWARFVariable> stackResults = new ArrayList<>();
//		// TODO: zero-length items also need to be segregated at the end of the struct
//		for (DWARFVariable dvar : returnParams) {
//			List<Register> regs = storageAllocator.getRegistersFor(dvar.type);
//			if (regs == null || regs.isEmpty()) {
//				stackResults.add(dvar);
//			}
//			else {
//				struct.add(dvar.type, dvar.name.getName(), regs.toString());
//			}
//		}
//
//		boolean be = dfunc.getProgram().isBigEndian();
//
//		// add these to the struct last or first, depending on endianness
//		for (int i = 0; i < stackResults.size(); i++) {
//			DWARFVariable dvar = stackResults.get(i);
//			if (be) {
//				struct.add(dvar.type, dvar.name.getName(), "stack");
//			}
//			else {
//				struct.insert(i, dvar.type, -1, dvar.name.getName(), "stack");
//			}
//		}
//
//		return struct;
//	}

	private void exportOrigFuncDef(DWARFFunction dfunc, DataTypeManager dtm) {
		try {
			FunctionDefinition funcDef = dfunc.asFuncDef();
			funcDef.setCategoryPath(GOLANG_API_EXPORT);
			dtm.addDataType(funcDef, DataTypeConflictHandler.KEEP_HANDLER);
		}
		catch (DuplicateNameException e) {
			// skip
		}
	}

	private GoVer getGolangVersion(DWARFFunction dfunc) {
		DWARFProgram dprog = dfunc.getProgram();
		GoVer ver = dprog.getOpaqueProperty(GoVer.class, null, GoVer.class);
		if (ver == null) {
			GoBuildInfo goBuildInfo = GoBuildInfo.fromProgram(dprog.getGhidraProgram());
			ver = goBuildInfo != null ? goBuildInfo.getVerEnum() : GoVer.UNKNOWN;
			dprog.setOpaqueProperty(GoVer.class, ver);
		}
		return ver;
	}

	private static final String GOLANG_ZEROBASE_ADDR = "GOLANG_ZEROBASE_ADDR";

	private Address getZerobaseAddress(DWARFFunction dfunc) {
		DWARFProgram dprog = dfunc.getProgram();
		Address zerobaseAddr = dprog.getOpaqueProperty(GOLANG_ZEROBASE_ADDR, null, Address.class);
		if (zerobaseAddr == null) {
			zerobaseAddr = GolangSymbolAnalyzer.getZerobaseAddress(dprog.getGhidraProgram());
			dprog.setOpaqueProperty(GOLANG_ZEROBASE_ADDR, zerobaseAddr);
		}
		return zerobaseAddr;
	}
}
