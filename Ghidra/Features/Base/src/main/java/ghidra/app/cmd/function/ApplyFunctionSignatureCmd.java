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
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;
import ghidra.program.util.DataTypeCleaner;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Command to create apply a function signature at an address.
 *
 * {@link Function} signature changes are applied using 
 * {@link Function#updateFunction(String, Variable, List, FunctionUpdateType, boolean, SourceType)}
 * with an update type of {@link FunctionUpdateType#DYNAMIC_STORAGE_FORMAL_PARAMS}.
 */
public class ApplyFunctionSignatureCmd extends BackgroundCommand<Program> {
	private Address entryPt;
	private SourceType source;
	private FunctionRenameOption functionRenameOption;
	private boolean preserveCallingConvention;
	private boolean applyEmptyComposites;
	private DataTypeConflictHandler conflictHandler;
	private FunctionSignature signature;
	private Program program;

	/**
	 * Constructs a new command for applying a signature to an existing function.
	 * <br>
	 * Only a function with a default name will be renamed to the function signature's name
	 * (see {@link FunctionRenameOption#RENAME_IF_DEFAULT}).
	 * <br>
	 * All datatypes will be resolved using the 
	 * {@link DataTypeConflictHandler#DEFAULT_HANDLER default conflict handler}.
	 * 
	 * @param entry     entry point address for the function to be created.
	 * @param signature function signature to apply
	 * @param source    the source of this function signature
	 */
	public ApplyFunctionSignatureCmd(Address entry, FunctionSignature signature,
			SourceType source) {
		this(entry, signature, source, false, false, DataTypeConflictHandler.DEFAULT_HANDLER,
			FunctionRenameOption.RENAME_IF_DEFAULT);
	}

	/**
	 * Constructs a new command for applying a signature to an existing function.
	 * <br>
	 * All datatypes will be resolved using the 
	 * {@link DataTypeConflictHandler#DEFAULT_HANDLER default conflict handler}.
	 * 
	 * @param entry     entry point address for the function to be created.
	 * @param signature function signature to apply
	 * @param source    the source of this function signature
	 * @param preserveCallingConvention if true the function calling convention will not be changed
	 * @param forceSetName true if name of the function should be set to the name, otherwise name
	 *                     will only be set name if currently default (e.g., FUN_1234). A value of 
	 *                     true is equivalent to {@link FunctionRenameOption#RENAME}, while a value
	 *                     of false is equivalent to {@link FunctionRenameOption#RENAME_IF_DEFAULT}.
	 */
	@Deprecated(since = "10.3", forRemoval = true)
	public ApplyFunctionSignatureCmd(Address entry, FunctionSignature signature, SourceType source,
			boolean preserveCallingConvention, boolean forceSetName) {
		this(entry, signature, source, preserveCallingConvention, false,
			DataTypeConflictHandler.DEFAULT_HANDLER,
			forceSetName ? FunctionRenameOption.RENAME : FunctionRenameOption.RENAME_IF_DEFAULT);
	}

	/**
	 * Constructs a new command for applying a signature to an existing function.
	 * <br>
	 * All datatypes will be resolved using the 
	 * {@link DataTypeConflictHandler#DEFAULT_HANDLER default conflict handler}.
	 * 
	 * @param entry     entry point address for the function to be created.
	 * @param signature function signature to apply
	 * @param source    the source of this function signature
	 * @param preserveCallingConvention if true the function calling convention will not be changed
	 * @param functionRenameOption controls renaming of the function using the name from the 
	 *                       specified function signature.
	 */
	@Deprecated(since = "11.0", forRemoval = true)
	public ApplyFunctionSignatureCmd(Address entry, FunctionSignature signature, SourceType source,
			boolean preserveCallingConvention, FunctionRenameOption functionRenameOption) {
		this(entry, signature, source, preserveCallingConvention, false,
			DataTypeConflictHandler.DEFAULT_HANDLER, functionRenameOption);
	}

	/**
	 * Constructs a new command for applying a signature to an existing function.
	 * 
	 * @param entry     entry point address for the function to be created.
	 * @param signature function signature to apply
	 * @param source    the source of this function signature
	 * @param preserveCallingConvention if true the function calling convention will not be changed
	 * @param applyEmptyComposites If true, applied composites will be resolved without their
	 *                        respective components if the type does not already exist in the 
	 *                        destination datatype manager.  If false, normal type resolution 
	 *                        will occur.
	 * @param conflictHandler conflict handler to be used when applying datatypes to the
	 *                        destination program.  If this value is not null or 
	 *                        {@link DataTypeConflictHandler#DEFAULT_HANDLER} the datatypes will be 
	 *                        resolved prior to updating the destinationFunction.  This handler
	 *                        will provide some control over how applied datatype are handled when 
	 *                        they conflict with existing datatypes. 
	 *                        See {@link DataTypeConflictHandler} which provides some predefined
	 *                        handlers.
	 * @param functionRenameOption controls renaming of the function using the name from the 
	 *                        specified function signature.
	 */
	public ApplyFunctionSignatureCmd(Address entry, FunctionSignature signature, SourceType source,
			boolean preserveCallingConvention, boolean applyEmptyComposites,
			DataTypeConflictHandler conflictHandler, FunctionRenameOption functionRenameOption) {
		super("Create Function", true, false, false);
		this.entryPt = entry;
		this.signature = signature;
		this.source = source;
		this.preserveCallingConvention = preserveCallingConvention;
		this.applyEmptyComposites = applyEmptyComposites;
		this.conflictHandler =
			(conflictHandler == null) ? DataTypeConflictHandler.DEFAULT_HANDLER : conflictHandler;
		this.functionRenameOption = functionRenameOption;
	}

	private DataType prepareDataType(DataType dt, DataTypeManager destinationDtm,
			DataTypeCleaner dtCleaner) {
		if (dtCleaner != null) {
			dt = dtCleaner.clean(dt);
		}
		if (conflictHandler != DataTypeConflictHandler.DEFAULT_HANDLER) {
			dt = destinationDtm.resolve(dt, conflictHandler);
		}
		return dt;
	}

	@Override
	public boolean applyTo(Program p, TaskMonitor monitor) {
		this.program = p;

		Function func = program.getListing().getFunctionContaining(entryPt);

		if (func == null) {
			return false;
		}

		monitor.setMessage("Rename " + func.getName());

		try {
			setSignature(func);
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
	 * Sets a function's signature in the program using the command details.
	 * @param func the function
	 */
	private boolean setSignature(Function func) throws InvalidInputException {

		// take on the signatures name if this is not a user defined symbol
		String name = signature.getName();
		setName(func, name);

		CompilerSpec compilerSpec = program.getCompilerSpec();
		String conventionName = getCallingConvention(func, compilerSpec);
		DataType returnDt = signature.getReturnType();
		ParameterDefinition[] args = signature.getArguments();

		ProgramBasedDataTypeManager targetDtm = func.getProgram().getDataTypeManager();
		DataTypeCleaner dtCleaner =
			applyEmptyComposites ? new DataTypeCleaner(targetDtm, true) : null;
		try {
			if (dtCleaner != null || conflictHandler != DataTypeConflictHandler.DEFAULT_HANDLER) {
				for (ParameterDefinition arg : args) {
					arg.setDataType(prepareDataType(arg.getDataType(), targetDtm, dtCleaner));
				}
				returnDt = prepareDataType(returnDt, targetDtm, dtCleaner);
			}

			ReturnParameterImpl returnParam = new ReturnParameterImpl(returnDt, program);
			List<Parameter> params =
				createParameters(compilerSpec, conventionName, args, returnParam);

			SymbolTable symbolTable = program.getSymbolTable();

			adjustParameterNamesToAvoidConflicts(symbolTable, func, params);

			func.updateFunction(conventionName, returnParam, params,
				FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, false, source);
			func.setVarArgs(signature.hasVarArgs());

			// Only apply noreturn if signature has it set
			if (signature.hasNoReturn()) {
				func.setNoReturn(signature.hasNoReturn());
			}
		}
		catch (DuplicateNameException e) {
			// should not happen unless caused by a concurrent operation
			throw new InvalidInputException(
				"Parameter name conflict, likely due to concurrent operation");
		}
		finally {
			if (dtCleaner != null) {
				dtCleaner.close();
			}
		}

		updateStackPurgeSize(func, program);

		return true;
	}

	private List<Parameter> createParameters(CompilerSpec compilerSpec, String conventionName,
			ParameterDefinition[] args, Parameter returnParam) throws InvalidInputException {

		DataType returnDt = returnParam.getDataType();

		int firstParamIndex = getIndexOfFirstParameter(conventionName, args);

		List<Parameter> params = new ArrayList<>();
		boolean settleCTypes = compilerSpec.doesCDataTypeConversions();
		DataTypeManager dtm = program.getDataTypeManager();
		for (int i = firstParamIndex; i < args.length; i++) {
			String name = args[i].getName();
			DataType type = args[i].getDataType().clone(dtm);
			if (Function.RETURN_PTR_PARAM_NAME.equals(name)) {
				if ((type instanceof Pointer) &&
					(type.isEquivalent(returnDt) || VoidDataType.dataType.isEquivalent(returnDt))) {
					returnParam.setDataType(((Pointer) type).getDataType(), source);
				}
				continue; // remove what should be an auto-param
			}

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

		for (Parameter param : params) {
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

		if (!conventionName.startsWith(CompilerSpec.CALLING_CONVENTION_thiscall)) {
			return 0;
		}

		if (!Function.THIS_PARAM_NAME.equals(args[0].getName())) {
			return 0;
		}

		// Ignore this parameter since it should be established as an auto-parameter
		return 1; // 'this call' and the first param's name is 'this'
	}

	private String getCallingConvention(Function function, CompilerSpec compilerSpec) {

		// Ignore signature's calling convention if unknown/not-defined
		String callingConvention = signature.getCallingConventionName();
		if (compilerSpec.getCallingConvention(callingConvention) == null) {
			callingConvention = null;
		}

		// Continue using function's current calling convention if valid and either
		// reservation was requested or signature's convention is unknown/not-defined.
		PrototypeModel currentConvention = function.getCallingConvention();
		if (currentConvention != null && (callingConvention == null || preserveCallingConvention)) {
			callingConvention = function.getCallingConventionName();
		}

		return callingConvention;
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

	/**
	 * 
	 * @param function function to be renamed
	 * @param name function name to be applied
	 * @throws InvalidInputException if invalid name is specified or a duplicate name occurs
	 */
	private void setName(Function function, String name) throws InvalidInputException {

		if (functionRenameOption == FunctionRenameOption.NO_CHANGE || name == null) {
			return;
		}

		SymbolUtilities.validateName(name);
		if (function.getName().equals(name)) {
			return;
		}

		if (functionRenameOption == FunctionRenameOption.RENAME_IF_DEFAULT &&
			function.getSymbol().getSource() != SourceType.DEFAULT) {
			// not default and we are not forcing the rename
			return;
		}

		try {
			removeCodeSymbol(function.getEntryPoint(), name, function.getParentNamespace());
			function.setName(name, source);
		}
		catch (DuplicateNameException e) {
			// unexpected
			throw new InvalidInputException(
				"Function name conflict occurred when applying function signature.");
		}
	}

	/**
	 * The C language assumes array datatypes are passed simply as pointers (by reference) even though
	 * other datatypes are passed by value.  This routine converts the datatype to the appropriate pointer
	 * in situations where we need to get at the exact type being passed by "value"
	 * @param dt the type
	 * @param dtm the data type manager
	 * @return the updated type
	 */
	private static DataType settleCDataType(DataType dt, DataTypeManager dtm) {
		if (dt == null) {
			return null;
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

	private void removeCodeSymbol(Address address, String name, Namespace namespace) {
		SymbolTable symbolTable = program.getSymbolTable();
		Symbol otherSym = symbolTable.getSymbol(name, address, namespace);
		if (otherSym != null && otherSym.getSymbolType() == SymbolType.LABEL) {
			otherSym.delete(); // remove label so function rename may use it
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
