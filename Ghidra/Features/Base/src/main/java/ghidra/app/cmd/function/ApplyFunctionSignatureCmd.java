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
package ghidra.app.cmd.function;

import java.util.ArrayList;
import java.util.List;

import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Command to create apply a function signature at an address.
 *
 *
 */
public class ApplyFunctionSignatureCmd extends BackgroundCommand {
	private Address entryPt;
	private SourceType source;
	private boolean setName;
	private boolean preserveCallingConvention;
	private FunctionSignature signature;
	private Program program;

	/**
	 * Constructs a new command for creating a function.
	 * @param entry entry point address for the function to be created.
	 * @param signature function signature to apply
	 * @param source the source of this function signature
	 */
	public ApplyFunctionSignatureCmd(Address entry, FunctionSignature signature,
			SourceType source) {
		this(entry, signature, source, false, false);
	}

	/**
	 * Constructs a new command for creating a function.
	 * @param entry entry point address for the function to be created.
	 * @param signature function signature to apply
	 * @param source the source of this function signature
	 * @param preserveCallingConvention if true the function calling convention will not be changed
	 * @param setName true if name of the function should be set to the name
	 * of the signature
	 */
	public ApplyFunctionSignatureCmd(Address entry, FunctionSignature signature, SourceType source,
			boolean preserveCallingConvention, boolean setName) {
		super("Create Function", true, false, false);
		this.entryPt = entry;
		this.signature = signature;
		this.source = source;
		this.preserveCallingConvention = preserveCallingConvention;
		this.setName = setName;
	}

	/**
	 *
	 * @see ghidra.framework.cmd.BackgroundCommand#applyTo(ghidra.framework.model.DomainObject, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		program = (Program) obj;

		Function func = program.getListing().getFunctionContaining(entryPt);

		if (func == null) {
			return false;
		}

		monitor.setMessage("Rename " + func.getName());

		try {
			setSignature(func, signature, preserveCallingConvention, setName, source);
		}
		catch (InvalidInputException e) {
			Msg.warn(this, e.getMessage());
			setStatusMsg(e.getMessage());
			return false;
		}
		catch (Exception e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			setStatusMsg("Invalid signature");
			return false;
		}

		return true;
	}

	/**
	 * Sets a function's signature in the program.
	 * @param program The program containing the function.
	 * @param func the function
	 * @param signature the signature to apply
	 * @param preserveCallingConvention if true, the functions calling convention will not be modified
	 * @param forceName force the name of the signature onto the function
	 *                  normally the name is only set on default function names (not user-defined).
	 * @param source the source of this function signature
	 */
	private boolean setSignature(Function func, FunctionSignature signature,
			boolean preserveCallingConvention, boolean forceName, SourceType source)
			throws InvalidInputException {

		// take on the signatures name if this is not a user defined symbol
		String name = signature.getName();
		setName(func, name, source, forceName);

		CompilerSpec compilerSpec = program.getCompilerSpec();
		String conventionName = getCallingConvention(func, compilerSpec);

		ParameterDefinition[] args = signature.getArguments();
		List<Parameter> params = createParameters(compilerSpec, conventionName, args);

		SymbolTable symbolTable = program.getSymbolTable();
		try {

			adjustParameterNamesToAvoidConflicts(symbolTable, func, params);

			ReturnParameterImpl returnParam =
				new ReturnParameterImpl(signature.getReturnType(), program);

			func.updateFunction(conventionName, returnParam, params,
				FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, false, source);
			func.setVarArgs(signature.hasVarArgs());
		}
		catch (DuplicateNameException e) {
			// should not happen unless caused by a concurrent operation
			throw new InvalidInputException(
				"Parameter name conflict, likely due to concurrent operation");
		}

		updateStackPurgeSize(func, program);

		return true;
	}

	private List<Parameter> createParameters(CompilerSpec compilerSpec, String conventionName,
			ParameterDefinition[] args) throws InvalidInputException {

		int firstParamIndex = getIndexOfFirstParameter(conventionName, args);

		List<Parameter> params = new ArrayList<>();
		boolean settleCTypes = compilerSpec.doesCDataTypeConversions();
		DataTypeManager dtm = program.getDataTypeManager();
		for (int i = firstParamIndex; i < args.length; i++) {
			String name = args[i].getName();
			if (Function.RETURN_PTR_PARAM_NAME.equals(name)) {
				continue; // discard what should be an auto-param
			}

			DataType type = args[i].getDataType().clone(dtm);
			if (settleCTypes) {
				type = settleCDataType(type, dtm);
			}
			Parameter param =
				new ParameterImpl(name, type, VariableStorage.UNASSIGNED_STORAGE, program);
			param.setComment(args[i].getComment());
			params.add(param);
		}
		return params;
	}

	private void adjustParameterNamesToAvoidConflicts(SymbolTable symbolTable, Function function,
			List<Parameter> params) throws DuplicateNameException, InvalidInputException {

		for (int i = 0; i < params.size(); i++) {
			Parameter param = params.get(i);
			String name = param.getName();
			if (name == null || SymbolUtilities.isDefaultParameterName(name)) {
				continue;
			}

			String uniqueName = getUniqueParameterName(symbolTable, function, name);
			param.setName(uniqueName, param.getSource());
		}
	}

	private int getIndexOfFirstParameter(String conventionName, ParameterDefinition[] args) {

		if (args.length == 0) {
			return 0;
		}

		if (!CompilerSpec.CALLING_CONVENTION_thiscall.equals(conventionName)) {
			return 0;
		}

		if (!Function.THIS_PARAM_NAME.equals(args[0].getName())) {
			return 0;
		}

		// Ignore this parameter since it should be established as an auto-parameter
		return 1; // 'this call' and the first param's name is 'this'
	}

	private String getCallingConvention(Function function, CompilerSpec compilerSpec) {
		PrototypeModel preferredModel = null;
		if (signature.getGenericCallingConvention() != GenericCallingConvention.unknown) {
			preferredModel = compilerSpec.matchConvention(signature.getGenericCallingConvention());
		}

		PrototypeModel convention = function.getCallingConvention();
		if (convention == null || !preserveCallingConvention) {
			convention = preferredModel;
// NOTE: This has been disable since it can cause imported signature information to be 
// ignored and overwritten by subsequent analysis
//			if (convention == null && compilerSpec.getCallingConventions().length > 1) {
//				// use default source for signature if convention is really unknown so that we
//				// know dynamic storage assignment is unreliable
//				source = SourceType.DEFAULT;
//			}
		}

		// Calling convention is permitted to change
		String conventionName = function.getCallingConventionName();
		if (!preserveCallingConvention && convention != null) {
			conventionName = convention.getName();
		}
		return conventionName;
	}

	private static void updateStackPurgeSize(Function function, Program program) {

		// TODO: The following code could lock-in the wrong purge if the signature or calling
		// convention is incorrect.  (See SCR 9580)
		if (function.isStackPurgeSizeValid()) {
			return;
		}

		PrototypeModel convention = function.getCallingConvention();
		if (convention == null) {
			convention = program.getCompilerSpec().getDefaultCallingConvention();
		}

		int extraPop = convention.getExtrapop();
		if (extraPop != PrototypeModel.UNKNOWN_EXTRAPOP) {
			function.setStackPurgeSize(0);
			return;
		}

		int purgeSize = 0;
		Parameter[] parameters = function.getParameters();
		if (parameters.length > 0) {
			int align = convention.getStackParameterAlignment();
			long min = 0xfffffff0L; // Make sure this is a big POSITIVE value
			long max = 0;
			for (Parameter parameter : parameters) {
				Varnode vn = parameter.getFirstStorageVarnode();
				if (vn == null) {
					purgeSize = Function.UNKNOWN_STACK_DEPTH_CHANGE;
					break;
				}
				if (!vn.getAddress().isStackAddress()) {
					continue;
				}
				long val = vn.getOffset();
				if (val < min) {
					min = val;
				}
				val += vn.getSize();
				if (val > max) {
					max = val;
				}
			}

			if (max > min) {
				int diff = (int) (max - min);
				int rem = diff % align;
				if (rem != 0) {
					diff += (align - rem);
				}
				purgeSize += diff;
			}
		}

		if (purgeSize >= 0 && purgeSize != Function.UNKNOWN_STACK_DEPTH_CHANGE) {
			function.setStackPurgeSize(purgeSize);
		}
	}

	private static void setName(Function function, String name, SourceType source,
			boolean forceName) throws InvalidInputException {

		if (name == null) {
			return;
		}

		Program program = function.getProgram();
		Address entryPoint = function.getEntryPoint();
		SymbolUtilities.validateName(name);

		SymbolTable symbolTable = program.getSymbolTable();
		Symbol sym = symbolTable.getPrimarySymbol(entryPoint);
		if (sym == null || sym.getName().equals(name)) {
			return;
		}

		if (!forceName && sym.getSource() != SourceType.DEFAULT) {
			// not default and we are not forcing the rename
			return;
		}

		try {
			removeCodeSymbol(symbolTable, entryPoint, name, function.getParentNamespace());
			sym.setName(name, source);
		}
		catch (DuplicateNameException e) {
			throw new InvalidInputException(
				"Function name conflict occurred when applying function signature.");
		}

	}

	/**
	 * The C language assumes array datatypes are passed simply as pointers (by reference) even though
	 * other datatypes are passed by value.  This routine converts the datatype to the appropriate pointer
	 * in situations where we need to get at the exact type being passed by "value"
	 * @param dt
	 * @return
	 */
	public static DataType settleCDataType(DataType dt, DataTypeManager dtm) {
		if (dt == null) {
			return dt;
		}
		DataType baseType = dt;
		if (baseType instanceof TypedefDataType) {
			baseType = ((TypedefDataType) baseType).getBaseDataType();
		}
		if (!(baseType instanceof ArrayDataType)) {
			return dt;
		}
		baseType = ((ArrayDataType) baseType).getDataType();
		return dtm.getPointer(baseType);
	}

	private static String getUniqueParameterName(SymbolTable symbolTable, Function function,
			String name) {
		if (name == null || !SymbolUtilities.isDefaultParameterName(name)) {
			return name;
		}
		Symbol s = symbolTable.getParameterSymbol(name, function);
		if (s == null || s.getSymbolType() == SymbolType.PARAMETER) {
			return name;
		}
		return getUniqueName(symbolTable, function, name);
	}

	private static void removeCodeSymbol(SymbolTable symbolTable, Address address, String name,
			Namespace namespace) {
		Symbol otherSym = symbolTable.getSymbol(name, address, namespace);
		if (otherSym != null) {
			if (otherSym.getSymbolType() == SymbolType.LABEL) {
				otherSym.delete(); // replace label if function name matches
			}
		}
	}

	private static String getUniqueName(SymbolTable symbolTable, Namespace namespace,
			String baseName) {
		String name = baseName;
		if (name != null) {
			// establish unique name
			int cnt = 0;
			while (!symbolTable.getSymbols(name, namespace).isEmpty()) {
				name = baseName + (++cnt);
			}
		}
		return name;
	}

}
