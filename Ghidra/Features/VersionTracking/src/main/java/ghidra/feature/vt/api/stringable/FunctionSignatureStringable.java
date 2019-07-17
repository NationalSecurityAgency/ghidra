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
package ghidra.feature.vt.api.stringable;

import static ghidra.feature.vt.gui.util.VTOptionDefines.*;

import java.util.*;

import ghidra.feature.vt.api.util.Stringable;
import ghidra.feature.vt.api.util.VersionTrackingApplyException;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.*;
import ghidra.feature.vt.gui.util.VTOptionDefines;
import ghidra.framework.options.ToolOptions;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.symbol.*;
import ghidra.program.util.FunctionUtility;
import ghidra.util.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class FunctionSignatureStringable extends Stringable {

	private static final String EMPTY_STRING = "";
	private static final String MAKE_POINTER_PREFIX = "*";

	public static final String SHORT_NAME = "FUNCTION_SIG";

	private static String PARAMETER_STORAGE_DELIMITER = ";";
	private static final String PARAMETER_INFO_DELIMITER = DOUBLE_DELIMITER;

	private String signatureString;
	private String originalName;
	private SourceType signatureSource;
	private String callingConventionName;
	private boolean isInline = false;
	private boolean hasNoReturn = false;
	private boolean hasVarargs = false;
	private String callFixup;
	private boolean hasCustomStorage = false;
	private ParameterInfo returnInfo;
	private List<ParameterInfo> parameterInfos = new ArrayList<>();
	private boolean isThisCall = false;

	private Program program; // Needed for converting variable storage to a displayable string.

	public FunctionSignatureStringable() {
		super(SHORT_NAME);
	}

	public FunctionSignatureStringable(Function function) {
		super(SHORT_NAME);
		program = function.getProgram();

		originalName = function.getName();

		this.isInline = function.isInline();
		this.hasNoReturn = function.hasNoReturn();
		this.hasVarargs = function.hasVarArgs();
		this.callingConventionName = function.getCallingConventionName();
		this.callFixup = function.getCallFixup();

		// The Function Signature cares about the signature source, custom storage,
		// return type/storage, calling convention, parameter data type/storage,
		// parameter names and source types, parameter comments, varArgs,
		// inline flag, no return flag, and call fixup.

		this.signatureSource = function.getSignatureSource();
		this.hasCustomStorage = function.hasCustomVariableStorage();

		GenericCallingConvention guessedCallingConvention =
			GenericCallingConvention.guessFromName(function.getCallingConventionName());
		isThisCall = (guessedCallingConvention == GenericCallingConvention.thiscall);

		// ignore source from function return which is same as signature source
		returnInfo = getParameterInfo(function.getReturn(), SourceType.DEFAULT);

		for (Parameter parameter : function.getParameters()) {
			parameterInfos.add(getParameterInfo(parameter, parameter.getSource()));
		}
		this.callFixup = function.getCallFixup();
	}

	private ParameterInfo getParameterInfo(Parameter parameter, SourceType source) {
		String name = parameter.getName(); // default names can be significant!
		String comment = parameter.getComment();
		DataType dt = parameter.getDataType();
		String paramStorage = parameter.getVariableStorage().getSerializationString();
		return new ParameterInfo(dt, name, paramStorage, source, comment);
	}

	public boolean hasCustomStorage() {
		return hasCustomStorage;
	}

	public boolean hasVarArgs() {
		return hasVarargs;
	}

	private String getSignatureDisplayString() {
		if (signatureString != null) {
			return signatureString;
		}
		StringBuffer buf = new StringBuffer();
		buf.append(returnInfo.dataType.getDisplayName());
		buf.append(" ");

		if (isInline) {
			buf.append("inline ");
		}

		if (hasNoReturn) {
			buf.append("noreturn ");
		}

		// include calling convention
		if (callingConventionName != null &&
			!callingConventionName.equals(Function.DEFAULT_CALLING_CONVENTION_STRING) &&
			!callingConventionName.equals(Function.UNKNOWN_CALLING_CONVENTION_STRING)) {
			buf.append(callingConventionName);
			buf.append(" ");
		}

		buf.append(originalName);
		buf.append("(");

		int paramCnt = parameterInfos.size();
		boolean emptyList = true;
		for (int i = 0; i < paramCnt; i++) {
			ParameterInfo paramInfo = parameterInfos.get(i);
			buf.append(paramInfo.dataType.getDisplayName());
			buf.append(" ");
			buf.append(paramInfo.name);
			emptyList = false;
			if ((i < (paramCnt - 1)) || hasVarargs) {
				buf.append(", ");
			}
		}
		if (hasVarargs) {
			buf.append(FunctionSignature.VAR_ARGS_DISPLAY_STRING);
		}
		else if (emptyList && signatureSource != SourceType.DEFAULT) {
			buf.append(FunctionSignature.VOID_PARAM_DISPLAY_STRING);
		}
		buf.append(")");

		signatureString = buf.toString();
		return signatureString;
	}

	@Override
	public String getDisplayString() {
		if (returnInfo == null) {
			return "undefined " + SHORT_NAME + "()";
		}
		StringBuffer buf = new StringBuffer();
		buf.append(getSignatureDisplayString());
		if (hasCustomStorage && (program != null)) {
			try {
				buf.append("  CustomStorage: ");
				VariableStorage returnVariableStorage =
					VariableStorage.deserialize(program, returnInfo.storage);
				buf.append(returnVariableStorage.toString() + " ");
				buf.append("(");
				int numParams = parameterInfos.size();
				for (int i = 0; i < numParams; i++) {
					String parameterStorageString = parameterInfos.get(i).storage;
					VariableStorage variableStorage =
						VariableStorage.deserialize(program, parameterStorageString);
					buf.append(variableStorage.toString());
					if ((i < (numParams - 1)) || hasVarargs) {
						buf.append(", ");
					}
				}
				if (hasVarargs) {
					buf.append(FunctionSignature.VAR_ARGS_DISPLAY_STRING);
				}
				buf.append(")");
			}
			catch (InvalidInputException e) {
				buf.append("Error getting variable storage.");
				e.printStackTrace();
			}
		}
		if (callFixup != null) {
			buf.append(" " + callFixup);
		}

		return buf.toString();
	}

	@Override
	protected String doConvertToString(Program desiredProgram) {
		if (returnInfo == null) {
			// not yet restored
			return EMPTY_STRING;
		}

		DataTypeManager dataTypeManager = desiredProgram.getDataTypeManager();
		StringBuilder buildy = new StringBuilder();
		buildy.append(getSavableFunctionSignatureSource()).append(DELIMITER);
		buildy.append(getSavableIsInline()).append(DELIMITER);
		buildy.append(getSavableHasNoReturn()).append(DELIMITER);
		buildy.append(getSavableCallingConvention()).append(DELIMITER);
		buildy.append(getSavableCallFixup()).append(DELIMITER);
		buildy.append(originalName).append(DELIMITER);
		buildy.append(getSavableHasCustomStorage()).append(DELIMITER);
		buildy.append(getSavableReturnType(dataTypeManager)).append(DELIMITER);
		buildy.append(getSavableReturnStorage()).append(DELIMITER);
		buildy.append(getSavableParameterStorage()).append(DELIMITER);
		buildy.append(getSavableVarArgs()).append(DELIMITER);
		buildy.append(Boolean.toString(isThisCall)).append(DELIMITER);
		buildy.append(saveParameterInfos());
		return buildy.toString();
	}

	private String getSavableReturnType(DataTypeManager dataTypeManager) {
		DataType dt = returnInfo.dataType;
		boolean makePointer = false;
		if (dt instanceof Pointer) {
			// handle auto-param/forced-indirect which may have unresolved pointer
			makePointer = true;
			dt = ((Pointer) dt).getDataType();
		}
		String str = Long.toString(dataTypeManager.getResolvedID(dt));
		if (makePointer) {
			str = MAKE_POINTER_PREFIX + str;
		}
		return str;
	}

	private String getSavableFunctionSignatureSource() {
		return signatureSource.name();
	}

	private String getSavableIsInline() {
		return Boolean.toString(isInline);
	}

	private String getSavableHasNoReturn() {
		return Boolean.toString(hasNoReturn);
	}

	private String getSavableCallingConvention() {
		return callingConventionName;
	}

	private String getSavableCallFixup() {
		if (callFixup == null) {
			return "none";
		}
		return callFixup;
	}

	private String getSavableHasCustomStorage() {
		return Boolean.toString(hasCustomStorage);
	}

	private String getSavableReturnStorage() {
		return returnInfo.storage;
	}

	private String getSavableParameterStorage() {
		StringBuilder storageBuilder = new StringBuilder();
		storageBuilder.append(parameterInfos.size()).append(PARAMETER_STORAGE_DELIMITER);
		for (ParameterInfo paramInfo : parameterInfos) {
			storageBuilder.append(paramInfo.storage).append(PARAMETER_STORAGE_DELIMITER);
		}
		return storageBuilder.toString();
	}

	private String getSavableVarArgs() {
		return Boolean.toString(hasVarargs);
	}

	@Override
	protected void doRestoreFromString(String string, Program desiredProgram) {
		signatureString = null;
		StringTokenizer tokenizer = new StringTokenizer(string, DELIMITER);
		List<String> strings = new LinkedList<>();
		while (tokenizer.hasMoreTokens()) {
			strings.add(tokenizer.nextToken());
		}

		program = desiredProgram;
		DataTypeManager dataTypeManager = desiredProgram.getDataTypeManager();

		signatureSource = SourceType.valueOf(strings.remove(0)); // Signature Source
		isInline = Boolean.parseBoolean(strings.remove(0)); // Inline Flag
		hasNoReturn = Boolean.parseBoolean(strings.remove(0)); // NoReturn Flag
		callingConventionName = strings.remove(0); // Calling Convention Name
		callFixup = strings.remove(0); // Call Fixup
		if (callFixup.equals("none")) {
			callFixup = null;
		}
		originalName = strings.remove(0); // Original Function Name
		hasCustomStorage = Boolean.parseBoolean(strings.remove(0)); // Custom Storage Flag
		String returnTypeID = strings.remove(0); // Return DataType ID with optional MAKE_POINTER_PREFIX
		String returnStorage = strings.remove(0); // Return Storage
		returnInfo = new ParameterInfo(returnTypeID, dataTypeManager, Parameter.RETURN_NAME,
			returnStorage, SourceType.DEFAULT, null);

		String parameterStorageString = strings.remove(0); // Parameter Storage
		// Now pull apart the parameter storage and put it in the list.
		StringTokenizer parameterTokenizer =
			new StringTokenizer(parameterStorageString, PARAMETER_STORAGE_DELIMITER);
		// parameterStorageCount currently guarantees there is something in the parameter storage token.
//		String parameterStorageCount = parameterTokenizer.nextToken();
		List<String> parameterStorage = new LinkedList<>();
		// TODO: do we need to check parameterStorageCount
		while (parameterTokenizer.hasMoreTokens()) {
			parameterStorage.add(parameterTokenizer.nextToken());
		}

		hasVarargs = Boolean.parseBoolean(strings.remove(0)); // VarArgs Flag
		isThisCall = Boolean.parseBoolean(strings.remove(0)); // "This" Calling Convention Flag

		// Now get the parameter info
		while (!strings.isEmpty()) {
			String parameterInfoString = strings.remove(0);
			// Now pull apart the parameter info.
			StringTokenizer parameterInfoTokenizer =
				new StringTokenizer(parameterInfoString, PARAMETER_INFO_DELIMITER);
			String dtIDString = parameterInfoTokenizer.nextToken();
			String name = parameterInfoTokenizer.nextToken();
			if (name != null && name.isEmpty()) {
				name = null;
			}
			String sourceAsName = parameterInfoTokenizer.nextToken();
			SourceType source = SourceType.valueOf(sourceAsName);
			String comment = null;
			try {
				comment = parameterInfoTokenizer.nextToken();
			}
			catch (NoSuchElementException e) {
				// Do nothing. There isn't a comment.
			}
			if (comment == null || comment.isEmpty()) {
				comment = null;
			}
			String decodedComment = decodeString(comment);

			String storage = null;
			int index = parameterInfos.size();
			if (parameterStorage.size() > index) {
				storage = parameterStorage.get(index);
			}

			parameterInfos.add(new ParameterInfo(dtIDString, dataTypeManager, name, storage, source,
				decodedComment));
		}
	}

	private boolean isDefaultParameterName(String name) {
		if (name == null) {
			return true;
		}
		return SymbolUtilities.isDefaultParameterName(name);
	}

	private String saveParameterInfos() {
		StringBuilder storageBuilder = new StringBuilder();
		int nameCount = parameterInfos.size();
		for (int i = 0; i < nameCount; i++) {
			ParameterInfo parameterInfo = parameterInfos.get(i);
			String name = parameterInfo.name;
			SourceType source = parameterInfo.source;
			String comment = parameterInfo.comment;
			if (comment == null) {
				comment = EMPTY_STRING;
			}
			String encodedComment = encodeString(comment);

			boolean makePointer = false;
			DataType dt = parameterInfo.dataType;
			if (dt instanceof Pointer) {
				// handle auto-param/forced-indirect which may have unresolved pointer
				makePointer = true;
				dt = ((Pointer) dt).getDataType();
			}
			long dataTypeID = program.getDataTypeManager().getResolvedID(dt);

			String serializedDataTypeID = Long.toString(dataTypeID);
			if (makePointer) {
				serializedDataTypeID = MAKE_POINTER_PREFIX + serializedDataTypeID;
			}
			storageBuilder.append(serializedDataTypeID).append(PARAMETER_INFO_DELIMITER);
			storageBuilder.append(name).append(PARAMETER_INFO_DELIMITER);
			storageBuilder.append(source.name()).append(PARAMETER_INFO_DELIMITER);
			storageBuilder.append(encodedComment).append(PARAMETER_INFO_DELIMITER);
			storageBuilder.append(DELIMITER);
		}
		return storageBuilder.toString();
	}

	@Override
	public int hashCode() {
		if (returnInfo == null) {
			return 0;
		}
		final int prime = 31;
		int result = 1;
		result = prime * result + originalName.hashCode();
		result = prime * result + returnInfo.dataType.getDisplayName().hashCode();
		for (ParameterInfo paramInfo : parameterInfos) {
			result = prime * result + paramInfo.dataType.getDisplayName().hashCode();
		}
		result = prime * result + ((callFixup == null) ? 0 : callFixup.hashCode());
		result = prime * result + (isInline ? 1 : 0);
		result = prime * result + (hasNoReturn ? 1 : 0);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if ((obj == null) || (getClass() != obj.getClass())) {
			return false;
		}
		FunctionSignatureStringable other = (FunctionSignatureStringable) obj;

		if (returnInfo == null) {
			// non-restored empty instance
			return other.returnInfo == null;
		}

		// Check our function signatures for equality.
		// They can differ by the signature source, calling convention, call fixup, return type,
		// parameters (data types, names and sources, comments), varArgs, inline flag,
		// no return flag, and storage.

		if (signatureSource != other.signatureSource) {
			return false;
		}
		if (hasCustomStorage != other.hasCustomStorage) {
			return false;
		}
		if (isInline != other.isInline) {
			return false;
		}
		if (hasNoReturn != other.hasNoReturn) {
			return false;
		}
		if (!SystemUtilities.isEqual(callFixup, other.callFixup)) {
			return false;
		}
		if (hasVarargs != other.hasVarargs) {
			return false;
		}
		if (!returnInfo.isEquivalent(other.returnInfo)) { // storage not checked
			return false;
		}
		int paramCnt = parameterInfos.size();
		if (paramCnt != other.parameterInfos.size()) {
			return false;
		}
		for (int i = 0; i < paramCnt; i++) { // storage not checked
			if (!parameterInfos.get(i).isEquivalent(other.parameterInfos.get(i))) {
				return false;
			}
		}
		return true;
	}

	public boolean sameFunctionSignature(Function function) {
		return equals(new FunctionSignatureStringable(function));
	}

	/**
	 *
	 * @param toFunction the function whose signature we are setting.
	 * @param markupOptions the options indicate what parts of the function signature to apply.
	 * @param forceApply true indicates that the function signature should be applied even if the
	 * function signature, return type, parameter data type or parameter name options are set
	 * to "do not apply".
	 * @throws VersionTrackingApplyException if all desired parts of the function signature couldn't be applied.
	 */
	public boolean applyFunctionSignature(Function toFunction, ToolOptions markupOptions,
			boolean forceApply) throws VersionTrackingApplyException {

		VTMatchApplyChoices.FunctionSignatureChoices functionSignatureChoice =
			markupOptions.getEnum(VTOptionDefines.FUNCTION_SIGNATURE,
				DEFAULT_OPTION_FOR_FUNCTION_SIGNATURE);

		int toParamCount = toFunction.getParameterCount();

		if ((functionSignatureChoice == FunctionSignatureChoices.WHEN_SAME_PARAMETER_COUNT) &&
			(toParamCount != parameterInfos.size())) {
			// Don't replace since number of parameters differs.
			Msg.debug(this, "Number of parameters differs so function signature not applied at " +
				toFunction.getEntryPoint() + ".");
			return false;
		}
		CommentChoices commentChoice =
			markupOptions.getEnum(PARAMETER_COMMENTS, DEFAULT_OPTION_FOR_PARAMETER_COMMENTS);

		// Set the parameters and their storage.
		try {

			applyInline(toFunction, isInline, markupOptions);
			applyNoReturn(toFunction, hasNoReturn, markupOptions);

			String conventionName = getCallingConvention(toFunction, markupOptions);

			// Adjust whether or not the resulting function will use custom storage.
			boolean useCustomStorage = false;
			if (hasCustomStorage != toFunction.hasCustomVariableStorage()) {
				// This should only change to use custom storage if same language.
				boolean sameLanguage =
					FunctionUtility.isSameLanguage(toFunction.getProgram(), program);
				if (!hasCustomStorage || (hasCustomStorage && sameLanguage)) {
					useCustomStorage = hasCustomStorage;
				}
			}

			Parameter returnParam =
				getReturnParameter(toFunction, markupOptions, forceApply, useCustomStorage);

			List<Parameter> newParams =
				getParameters(toFunction, markupOptions, forceApply, useCustomStorage);

			toFunction.updateFunction(conventionName, returnParam, newParams,
				useCustomStorage ? FunctionUpdateType.CUSTOM_STORAGE
						: FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
				true, signatureSource);
			if (forceApply) {
				// must force signatureSource if precedence has been lowered
				// TODO: Should any manual change in function signature force source to be USER_DEFINED instead ??
				toFunction.setSignatureSource(signatureSource);
			}
		}
		catch (DuplicateNameException e) {
			throw new VersionTrackingApplyException(e.getMessage(), e);
		}
		catch (InvalidInputException e) {
			throw new VersionTrackingApplyException(e.getMessage(), e);
		}

		boolean hasFromVarArgs = hasVarargs;
		boolean hasToVarArgs = toFunction.hasVarArgs();
		if (hasFromVarArgs != hasToVarArgs) {
			applyVarArgs(toFunction, hasFromVarArgs, markupOptions);
		}
		applyCallFixup(toFunction, callFixup, markupOptions);

		if (forceApply) {
			forceParameterNames(toFunction);
		}
		else {
			applyParameterNames(toFunction, markupOptions, true, toParamCount);
		}

		replaceParameterComments(toFunction, commentChoice);

		return true;
	}

	private void applyInline(Function toFunction, boolean fromFunctionIsInline,
			ToolOptions markupOptions) {
		ReplaceChoices inlineChoice = markupOptions.getEnum(INLINE, DEFAULT_OPTION_FOR_INLINE);
		if (inlineChoice == ReplaceChoices.EXCLUDE) {
			return; // Not replacing inline flag.
		}
		boolean toFunctionIsInline = toFunction.isInline();
		if (fromFunctionIsInline == toFunctionIsInline) {
			return;
		}
		if (inlineChoice == ReplaceChoices.REPLACE) {
			toFunction.setInline(fromFunctionIsInline);
		}
	}

	private Parameter getReturnParameter(Function toFunction, ToolOptions markupOptions,
			boolean forceApply, boolean useCustomStorage) throws InvalidInputException {
		Parameter returnParam = toFunction.getReturn();
		ParameterDataTypeChoices returnTypeChoice =
			markupOptions.getEnum(FUNCTION_RETURN_TYPE, DEFAULT_OPTION_FOR_FUNCTION_RETURN_TYPE);
		boolean onlyReplaceUndefineds =
			returnTypeChoice == ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY;
		if (returnTypeChoice == ParameterDataTypeChoices.EXCLUDE) {
			return returnParam; // Not replacing return type.
		}
		DataType toReturnType = toFunction.getReturnType();
		DataType fromReturnType = returnInfo.dataType;
		boolean isFromDefault = fromReturnType == DataType.DEFAULT;
		boolean isToDefault = toReturnType == DataType.DEFAULT;
		boolean isToUndefined = Undefined.isUndefined(toReturnType);
		if (!forceApply && onlyReplaceUndefineds) {
			if (!isToDefault && !isToUndefined) {
				return returnParam; // can't do it because we should only replace undefined data types.
			}
		}
		if (!forceApply && isFromDefault) {
			return returnParam; // do nothing since default data type is lowest priority.
		}

		DataType returnType = (forceApply) ? fromReturnType
				: getHighestPriorityDataType(fromReturnType, toReturnType, onlyReplaceUndefineds);

		VariableStorage returnVariableStorage = VariableStorage.UNASSIGNED_STORAGE;
		if (useCustomStorage && returnInfo.storage != null) {
			returnVariableStorage =
				VariableStorage.deserialize(toFunction.getProgram(), returnInfo.storage);
		}
		return new ReturnParameterImpl(returnType, returnVariableStorage, toFunction.getProgram());
	}

	private void applyNoReturn(Function toFunction, boolean fromFunctionHasNoReturn,
			ToolOptions markupOptions) {
		ReplaceChoices noReturnChoice =
			markupOptions.getEnum(NO_RETURN, DEFAULT_OPTION_FOR_NO_RETURN);
		if (noReturnChoice == ReplaceChoices.EXCLUDE) {
			return; // Not replacing no return flag.
		}
		boolean toFunctionHasNoReturn = toFunction.hasNoReturn();
		if (fromFunctionHasNoReturn == toFunctionHasNoReturn) {
			return;
		}
		if (noReturnChoice == ReplaceChoices.REPLACE) {
			toFunction.setNoReturn(fromFunctionHasNoReturn);
		}
	}

	private void applyVarArgs(Function toFunction, boolean fromFunctionHasVarArgs,
			ToolOptions markupOptions) {
		ReplaceChoices varArgsChoice = markupOptions.getEnum(VAR_ARGS, DEFAULT_OPTION_FOR_VAR_ARGS);
		if (varArgsChoice == ReplaceChoices.EXCLUDE) {
			return; // Not replacing var args.
		}
		boolean toFunctionHasVarArgs = toFunction.hasVarArgs();
		if (fromFunctionHasVarArgs == toFunctionHasVarArgs) {
			return;
		}
		if (varArgsChoice == ReplaceChoices.REPLACE) {
			toFunction.setVarArgs(fromFunctionHasVarArgs);
		}
	}

	private void applyCallFixup(Function toFunction, String fromFunctionCallFixup,
			ToolOptions markupOptions) {
		ReplaceChoices callFixupChoice =
			markupOptions.getEnum(CALL_FIXUP, DEFAULT_OPTION_FOR_CALL_FIXUP);
		if (callFixupChoice == ReplaceChoices.EXCLUDE) {
			return; // Not replacing call fixup.
		}
		String toFunctionCallFixup = toFunction.getCallFixup();
		if (SystemUtilities.isEqual(fromFunctionCallFixup, toFunctionCallFixup)) {
			return;
		}
		if (callFixupChoice == ReplaceChoices.REPLACE) {
			// Check that you have the same cspec before trying to apply call fixup.
			if (FunctionUtility.isSameLanguage(toFunction.getProgram(), program)) {
				toFunction.setCallFixup(fromFunctionCallFixup);
			}
		}
	}

	private String getCallingConvention(Function toFunction, ToolOptions markupOptions) {
		boolean isFromUnknownCallingConvention = ((callingConventionName == null) ||
			callingConventionName.equals(Function.UNKNOWN_CALLING_CONVENTION_STRING));
		CallingConventionChoices callingConventionChoice =
			markupOptions.getEnum(CALLING_CONVENTION, DEFAULT_OPTION_FOR_CALLING_CONVENTION);
		String toCallingConventionName = toFunction.getCallingConventionName();
		if (SystemUtilities.isEqual(callingConventionName, toCallingConventionName)) {
			return callingConventionName;
		}
		Program toProgram = toFunction.getProgram();

		switch (callingConventionChoice) {
			case SAME_LANGUAGE:
				if (FunctionUtility.isSameLanguage(program, toProgram)) {
					return callingConventionName;
				}
				break;
			case NAME_MATCH:
				if (isFromUnknownCallingConvention ||
					hasNamedCallingConvention(callingConventionName, toProgram)) {
					return callingConventionName;
				}
				break;
			default:
				break;
		}
		return toCallingConventionName;
	}

	private boolean hasNamedCallingConvention(String myCallingConventionName,
			Program programToCheck) {
		Language language = programToCheck.getLanguage();
		CompilerSpec defaultCompilerSpec = language.getDefaultCompilerSpec();
		PrototypeModel callingConvention =
			defaultCompilerSpec.getCallingConvention(myCallingConventionName);
		return (callingConvention != null);
	}

	private List<Parameter> getParameters(Function toFunction, ToolOptions markupOptions,
			boolean forceApply, boolean useCustomStorage) throws InvalidInputException {

		// See what options the user has specified when applying parameter names.
		VTMatchApplyChoices.ParameterDataTypeChoices parameterDataTypesChoice =
			markupOptions.getEnum(VTOptionDefines.PARAMETER_DATA_TYPES,
				DEFAULT_OPTION_FOR_PARAMETER_DATA_TYPES);

		boolean onlyReplaceUndefineds =
			(parameterDataTypesChoice == ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);

		Program toProgram = toFunction.getProgram();
		Parameter[] toParameters = toFunction.getParameters();
		int toCount = toParameters.length;
		int parameterCount = parameterInfos.size();
		List<Parameter> parameters = new ArrayList<>();
		for (int i = 0; i < parameterCount; i++) {
			ParameterInfo paramInfo = parameterInfos.get(i);
			SourceType source = SourceType.DEFAULT;
			String name = source != SourceType.DEFAULT ? null : paramInfo.name; // defer setting non-default name
			String comment = paramInfo.comment;
			if (!forceApply && i < toCount) {
				name = toParameters[i].getName();
				source = toParameters[i].getSource();
				comment = toParameters[i].getComment();
			}
			DataType fromDataType = paramInfo.dataType;
			DataType toDataType = (i < toCount) ? toParameters[i].getDataType() : fromDataType;
			DataType dataType;
			if (forceApply) {
				dataType = fromDataType;
			}
			else if (parameterDataTypesChoice == ParameterDataTypeChoices.EXCLUDE) {
				dataType = toDataType;
			}
			else {
				dataType =
					getHighestPriorityDataType(fromDataType, toDataType, onlyReplaceUndefineds);
			}
			VariableStorage storage = VariableStorage.UNASSIGNED_STORAGE;
			if (useCustomStorage) {
				if ((i < toCount) && (dataType == toDataType)) {
					// FIXME! This can result in a storage collision!
					storage = toParameters[i].getVariableStorage();
				}
				else if (paramInfo.storage != null) {
					storage = VariableStorage.deserialize(toProgram, paramInfo.storage);
				}
			}
			// Use LocalVariableImpl so we can set source type
			Parameter param = new ParameterImpl(name, dataType, storage, toProgram, source);
			param.setComment(comment);
			parameters.add(param);
		}
		return parameters;
	}

	private DataType getHighestPriorityDataType(DataType fromDataType, DataType toDataType,
			boolean onlyReplaceUndefineds) {
		// Priority from highest to lowest is Defined, Undefined with size, Default.
		boolean fromIsDefault = fromDataType == DataType.DEFAULT;
		boolean toIsDefault = toDataType == DataType.DEFAULT;
		boolean fromIsUndefined = Undefined.isUndefined(fromDataType);
		boolean toIsUndefined = Undefined.isUndefined(toDataType);
		if (fromIsDefault) {
			return toDataType;
		}
		if (fromIsUndefined) {
			if (toIsDefault || (toIsUndefined && !onlyReplaceUndefineds)) {
				return fromDataType;
			}
			return toDataType;
		}
		// fromDataType is defined.
		if (toIsDefault || toIsUndefined || !onlyReplaceUndefineds) {
			return fromDataType;
		}
		return toDataType;
	}

	/**
	 *
	 * @param toFunction the function whose parameter names we are setting.
	 * @param markupOptions
	 * @param doNotReplaceWithDefaultNames flag indicating whether or not a parameter name can be
	 * replaced with a default name.
	 * @param originalToParamCount original number of parameters in toFunction
	 * @throws VersionTrackingApplyException
	 */
	public boolean applyParameterNames(Function toFunction, ToolOptions markupOptions,
			boolean doNotReplaceWithDefaultNames, int originalToParamCount)
			throws VersionTrackingApplyException {

		// See what options the user has specified when applying parameter names.
		VTMatchApplyChoices.SourcePriorityChoices parameterNamesChoice = markupOptions.getEnum(
			VTOptionDefines.PARAMETER_NAMES, DEFAULT_OPTION_FOR_PARAMETER_NAMES);
		VTMatchApplyChoices.HighestSourcePriorityChoices highestPriorityChoice =
			markupOptions.getEnum(VTOptionDefines.HIGHEST_NAME_PRIORITY,
				DEFAULT_OPTION_FOR_HIGHEST_NAME_PRIORITY);
		boolean replaceSamePriorityNames =
			markupOptions.getBoolean(PARAMETER_NAMES_REPLACE_IF_SAME_PRIORITY,
				DEFAULT_OPTION_FOR_PARAMETER_NAMES_REPLACE_IF_SAME_PRIORITY);

		int fromParameterCount = parameterInfos.size();
		int minParameterCount = Math.min(fromParameterCount, originalToParamCount);
		boolean duplicateNameOccurred =
			tryToSetNames(toFunction, doNotReplaceWithDefaultNames, parameterNamesChoice,
				highestPriorityChoice, replaceSamePriorityNames, minParameterCount);
		// If a duplicate name was created, then try applying again to see if it can now be set
		// to the desired name. A duplicate may have occurred due to changing order of parameters.
		if (duplicateNameOccurred) {
			tryToSetNames(toFunction, doNotReplaceWithDefaultNames, parameterNamesChoice,
				highestPriorityChoice, replaceSamePriorityNames, minParameterCount);
		}

		return true;
	}

	private boolean tryToSetNames(Function toFunction, boolean doNotReplaceWithDefaultNames,
			VTMatchApplyChoices.SourcePriorityChoices parameterNamesChoice,
			VTMatchApplyChoices.HighestSourcePriorityChoices highestPriorityChoice,
			boolean replaceSamePriorityNames, int minParameterCount)
			throws VersionTrackingApplyException {

		boolean duplicateNameOccurred = false;
		int paramCnt = parameterInfos.size();
		for (int i = 0; i < paramCnt; i++) {
			// Check the name against the options to see when we should set the name.
			ParameterInfo parameterInfo = parameterInfos.get(i);
			String fromName = parameterInfo.name;
			SourceType fromSource = parameterInfo.source;
			boolean fromIsDefaultName = (fromSource == SourceType.DEFAULT) || (fromName == null);
			Parameter toParameter = toFunction.getParameter(i);
			SourceType toSource = toParameter.getSource();
			String toName = (toSource != SourceType.DEFAULT) ? toParameter.getName() : null;
			boolean toIsDefaultName = (toSource == SourceType.DEFAULT) || (toName == null);
			if (fromIsDefaultName && (doNotReplaceWithDefaultNames || toIsDefaultName)) {
				continue;
			}
			if (SystemUtilities.isEqual(fromName, toName)) {
				continue;
			}
			if (i < minParameterCount) {
				switch (parameterNamesChoice) {
					case PRIORITY_REPLACE:
						if (highestPriorityChoice == HighestSourcePriorityChoices.IMPORT_PRIORITY_HIGHEST) {
							// Import, User, Analysis, Default.
							if (!isFirstHigherPriorityWhenImportedPriority(fromSource, toSource,
								replaceSamePriorityNames)) {
								continue;
							}
						}
						else {
							// User, Import, Analysis, Default.
							if (!isFirstHigherPriorityWhenUserPriority(fromSource, toSource,
								replaceSamePriorityNames)) {
								continue;
							}
						}
						break;
					case REPLACE_DEFAULTS_ONLY:
						if (!toIsDefaultName || fromIsDefaultName) {
							continue;
						}
						break;
					case REPLACE:
						// Always replace since defaults get handled by "if" before this "switch".
						break;
					case EXCLUDE:
					default:
						continue;
				}
			}

			try {
				toParameter.setName(fromName, fromSource);
			}
			catch (DuplicateNameException e) {
				SymbolTable symbolTable = toFunction.getProgram().getSymbolTable();
				String uniqueParameterName =
					getUniqueParameterName(symbolTable, toFunction, fromName);
				try {
					toParameter.setName(uniqueParameterName, fromSource);
					duplicateNameOccurred = true;
				}
				catch (DuplicateNameException e1) {
					throw new VersionTrackingApplyException(e1.getMessage(), e1);
				}
				catch (InvalidInputException e1) {
					throw new VersionTrackingApplyException(e1.getMessage(), e1);
				}
			}
			catch (InvalidInputException e) {
				throw new VersionTrackingApplyException(e.getMessage(), e);
			}
		}
		return duplicateNameOccurred;
	}

	/**
	 * Uses this stringable's parameter info to set the name and source types for the specified
	 * function. Even default names from the parameter info will replace a defined parameter
	 * name in the function.
	 * @param toFunction the function whose parameter names are to be changed using the names
	 * from this stringable.
	 * @return true if the names are replaced.
	 * @throws VersionTrackingApplyException
	 */
	private boolean forceParameterNames(Function toFunction) throws VersionTrackingApplyException {

		boolean duplicateNameOccurred = tryToForceNames(toFunction);
		if (duplicateNameOccurred) {
			// If a duplicate name was created, then try applying again to see if it can now be set
			// to the desired name. A duplicate may have occurred due to changing order of parameters.
			tryToForceNames(toFunction);
		}

		return true;
	}

	private boolean tryToForceNames(Function toFunction) throws VersionTrackingApplyException {
		boolean duplicateNameOccurred = false;
		int paramCnt = parameterInfos.size();
		for (int i = 0; i < paramCnt; i++) {
			ParameterInfo parameterInfo = parameterInfos.get(i);
			String fromName = parameterInfo.name;
			SourceType fromSource = parameterInfo.source;
			Parameter toParameter = toFunction.getParameter(i);
			if (toParameter.isAutoParameter()) {
				continue;
			}
			SourceType toSource = toParameter.getSource();
			String toName = (toSource != SourceType.DEFAULT) ? toParameter.getName() : null;
			if (SystemUtilities.isEqual(fromName, toName)) {
				continue;
			}
			try {
				toParameter.setName(fromName, fromSource);
			}
			catch (DuplicateNameException e) {
				SymbolTable symbolTable = toFunction.getProgram().getSymbolTable();
				String uniqueParameterName =
					getUniqueParameterName(symbolTable, toFunction, fromName);
				try {
					toParameter.setName(uniqueParameterName, fromSource);
					duplicateNameOccurred = true;
				}
				catch (DuplicateNameException e1) {
					throw new VersionTrackingApplyException(e1.getMessage(), e1);
				}
				catch (InvalidInputException e1) {
					throw new VersionTrackingApplyException(e1.getMessage(), e1);
				}
			}
			catch (InvalidInputException e) {
				throw new VersionTrackingApplyException(e.getMessage(), e);
			}
		}
		return duplicateNameOccurred;
	}

	private boolean isFirstHigherPriorityWhenUserPriority(SourceType first, SourceType second,
			boolean replaceSamePriorityNames) {
		if (first == second && first != SourceType.DEFAULT) {
			return replaceSamePriorityNames;
		}
		if (first == SourceType.USER_DEFINED) {
			return (second == SourceType.IMPORTED || second == SourceType.ANALYSIS ||
				second == SourceType.DEFAULT);
		}
		if (first == SourceType.IMPORTED) {
			return (second == SourceType.ANALYSIS || second == SourceType.DEFAULT);
		}
		if (first == SourceType.ANALYSIS) {
			return (second == SourceType.DEFAULT);
		}
		return false;
	}

	private boolean isFirstHigherPriorityWhenImportedPriority(SourceType first, SourceType second,
			boolean replaceSamePriorityNames) {
		if (first == second && first != SourceType.DEFAULT) {
			return replaceSamePriorityNames;
		}
		if (first == SourceType.IMPORTED) {
			return (second == SourceType.USER_DEFINED || second == SourceType.ANALYSIS ||
				second == SourceType.DEFAULT);
		}
		if (first == SourceType.USER_DEFINED) {
			return (second == SourceType.ANALYSIS || second == SourceType.DEFAULT);
		}
		if (first == SourceType.ANALYSIS) {
			return (second == SourceType.DEFAULT);
		}
		return false;
	}

	private void replaceParameterComments(Function toFunction, CommentChoices commentChoice) {

		if (commentChoice == CommentChoices.EXCLUDE) {
			return;
		}

		int fromParameterCount = parameterInfos.size();
		int toParameterCount = toFunction.getParameterCount();
		int minParameterCount = Math.min(fromParameterCount, toParameterCount);
		for (int i = 0; i < minParameterCount; i++) {
			// Check the comment against the options to see when we should apply the comment.
			ParameterInfo parameterInfo = parameterInfos.get(i);
			String fromComment = parameterInfo.comment;
			Parameter toParameter = toFunction.getParameter(i);
			String toComment = toParameter.getComment();
			if (SystemUtilities.isEqual(fromComment, toComment)) {
				continue;
			}
			if (commentChoice == CommentChoices.APPEND_TO_EXISTING) {
				String mergedComment = StringUtilities.mergeStrings(toComment, fromComment);
				if (mergedComment != null && mergedComment.length() == 0) {
					mergedComment = null;
				}
				if (!SystemUtilities.isEqual(mergedComment, toComment)) {
					toParameter.setComment(mergedComment);
				}
			}
			if (commentChoice == CommentChoices.OVERWRITE_EXISTING) {
				if (fromComment != null && fromComment.length() == 0) {
					fromComment = null;
				}
				toParameter.setComment(fromComment);
			}
		}
	}

	private class ParameterInfo {

		private final DataType dataType;
		private final String name;
		private final SourceType source;
		private final String comment;
		private final String storage;

		/**
		 * Create parameter info object
		 * @param dataTypeID
		 * @param makePointer if true the specified data-type identified by dataTypeID is wrapped in a pointer
		 * @param name
		 * @param source
		 * @param comment
		 */
		private ParameterInfo(DataType dataType, String name, String storage, SourceType source,
				String comment) {
			this.dataType = dataType;
			this.name = name;
			this.storage = storage;
			this.source = source;
			this.comment = comment;
			if (comment != null && comment.trim().length() == 0) {
				comment = null;
			}
		}

		private ParameterInfo(String serializedDataTypeID, DataTypeManager dtMgr, String name,
				String storage, SourceType source, String comment) {

			long dataTypeID = -1;
			boolean makePtr = false;
			if (serializedDataTypeID != null && !serializedDataTypeID.isEmpty()) {
				if (serializedDataTypeID.startsWith(MAKE_POINTER_PREFIX)) {
					makePtr = true;
					serializedDataTypeID =
						serializedDataTypeID.substring(MAKE_POINTER_PREFIX.length());
				}
				dataTypeID = Long.parseLong(serializedDataTypeID);
			}
			DataType dt = dtMgr.getDataType(dataTypeID);
			if (makePtr) {
				dt = new PointerDataType(dt, dtMgr);
			}
			this.dataType = dt;
			this.name = name;
			this.storage = storage;
			this.source = source;
			this.comment = comment;
			if (comment != null && comment.trim().length() == 0) {
				comment = null;
			}
		}

		boolean isEquivalent(ParameterInfo other) {
			if (source != other.source) {
				return false;
			}
			if (source != SourceType.DEFAULT && !name.equals(other.name)) {
				return false;
			}
			if (!SystemUtilities.isEqual(comment, other.comment)) {
				return false;
			}
			if (!DataTypeUtilities.isSameOrEquivalentDataType(dataType, other.dataType)) {
				return false;
			}
			return true;
		}

		@Override
		public String toString() {
			StringBuilder strBuilder = new StringBuilder();
			strBuilder.append("[");
			strBuilder.append(dataType.getName());
			strBuilder.append(" ");
			strBuilder.append(name);
			strBuilder.append("@");
			strBuilder.append(storage);
			strBuilder.append("]");
			return strBuilder.toString();
		}
	}

	private static String getUniqueParameterName(SymbolTable symbolTable, Function function,
			String baseName) {

		String name = baseName;
		if (name != null) {
			// establish unique name
			int cnt = 0;
			while (symbolTable.getVariableSymbol(name, function) != null) {
				name = baseName + (++cnt);
			}
		}
		return name;
	}
}
