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

import static ghidra.feature.vt.gui.util.VTMatchApplyChoices.ParameterDataTypeChoices.*;
import static ghidra.feature.vt.gui.util.VTOptionDefines.*;

import java.util.*;

import org.apache.commons.lang3.StringUtils;

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
import ghidra.program.util.DataTypeCleaner;
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

		/*
		 	The Function Signature cares about:
		 	 	signature source, custom storage, return type/storage, calling convention, 
		 	 	parameter:
		 	 	 	data type/storage, names, source types, comments, 
		 	 	varArgs, inline flag, no return flag, and call fixup.		 	
		 */

		this.signatureSource = function.getSignatureSource();
		this.hasCustomStorage = function.hasCustomVariableStorage();

		isThisCall = CompilerSpec.CALLING_CONVENTION_thiscall.equals(callingConventionName);

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
		VariableStorage storage = parameter.getVariableStorage();
		String storageString = storage.getSerializationString();
		return new ParameterInfo(dt, name, storageString, source, comment);
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

		StringBuilder buf = new StringBuilder();
		buf.append(returnInfo.dataType.getDisplayName());
		buf.append(' ');

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
			buf.append(' ');
		}

		buf.append(originalName);
		buf.append('(');

		int n = parameterInfos.size();
		boolean isVoid = n == 0;
		for (int i = 0; i < n; i++) {
			ParameterInfo paramInfo = parameterInfos.get(i);
			buf.append(paramInfo.dataType.getDisplayName());
			buf.append(' ');
			buf.append(paramInfo.name);
			if (i < n - 1 || hasVarargs) {
				buf.append(", ");
			}
		}

		if (hasVarargs) {
			buf.append(FunctionSignature.VAR_ARGS_DISPLAY_STRING);
		}
		else if (isVoid && signatureSource != SourceType.DEFAULT) {
			buf.append(FunctionSignature.VOID_PARAM_DISPLAY_STRING);
		}
		buf.append(')');

		signatureString = buf.toString();
		return signatureString;
	}

	@Override
	public String getDisplayString() {
		if (returnInfo == null) {
			return "undefined " + SHORT_NAME + "()";
		}

		StringBuilder buf = new StringBuilder();
		buf.append(getSignatureDisplayString());

		addCustomStorageText(buf);

		if (callFixup != null) {
			buf.append(' ').append(callFixup);
		}

		return buf.toString();
	}

	private void addCustomStorageText(StringBuilder buf) {
		if (!hasCustomStorage || program == null) {
			return;
		}

		buf.append("  CustomStorage: ");
		try {
			VariableStorage returnStorage =
				VariableStorage.deserialize(program, returnInfo.storage);
			buf.append(returnStorage).append(' ');
			buf.append('(');
			int n = parameterInfos.size();
			for (int i = 0; i < n; i++) {
				String storageString = parameterInfos.get(i).storage;
				VariableStorage variableStorage =
					VariableStorage.deserialize(program, storageString);
				buf.append(variableStorage);
				if (i < n - 1 || hasVarargs) {
					buf.append(", ");
				}
			}

			if (hasVarargs) {
				buf.append(FunctionSignature.VAR_ARGS_DISPLAY_STRING);
			}
			buf.append(')');
		}
		catch (InvalidInputException e) {
			buf.append("Error getting variable storage.");
			Msg.error(this, "Error getting variable storage.", e);
		}
	}

	@Override
	protected String doConvertToString(Program desiredProgram) {
		if (returnInfo == null) {
			// not yet restored
			return EMPTY_STRING;
		}

		DataTypeManager dataTypeManager = desiredProgram.getDataTypeManager();
		StringBuilder buf = new StringBuilder();
		buf.append(getSavableFunctionSignatureSource()).append(DELIMITER);
		buf.append(getSavableIsInline()).append(DELIMITER);
		buf.append(getSavableHasNoReturn()).append(DELIMITER);
		buf.append(getSavableCallingConvention()).append(DELIMITER);
		buf.append(getSavableCallFixup()).append(DELIMITER);
		buf.append(originalName).append(DELIMITER);
		buf.append(getSavableHasCustomStorage()).append(DELIMITER);
		buf.append(getSavableReturnType(dataTypeManager)).append(DELIMITER);
		buf.append(getSavableReturnStorage()).append(DELIMITER);
		buf.append(getSavableParameterStorage()).append(DELIMITER);
		buf.append(getSavableVarArgs()).append(DELIMITER);
		buf.append(Boolean.toString(isThisCall)).append(DELIMITER);
		buf.append(saveParameterInfos());
		return buf.toString();
	}

	private String getSavableReturnType(DataTypeManager dataTypeManager) {
		DataType dt = returnInfo.dataType;
		boolean makePointer = false;
		if (dt instanceof Pointer) {
			// handle auto-param/forced-indirect which may have unresolved pointer
			makePointer = true;
			dt = ((Pointer) dt).getDataType();
		}

		String id = Long.toString(dataTypeManager.getResolvedID(dt));
		if (makePointer) {
			id = MAKE_POINTER_PREFIX + id;
		}
		return id;
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
		StringBuilder buf = new StringBuilder();
		buf.append(parameterInfos.size()).append(PARAMETER_STORAGE_DELIMITER);
		for (ParameterInfo info : parameterInfos) {
			buf.append(info.storage).append(PARAMETER_STORAGE_DELIMITER);
		}
		return buf.toString();
	}

	private String getSavableVarArgs() {
		return Boolean.toString(hasVarargs);
	}

	@Override
	protected void doRestoreFromString(String string, Program desiredProgram) {
		signatureString = null;
		StringTokenizer tokenizer = new StringTokenizer(string, DELIMITER);
		Queue<String> strings = new LinkedList<>(); // use a queue since we remove from the front
		while (tokenizer.hasMoreTokens()) {
			strings.add(tokenizer.nextToken());
		}

		program = desiredProgram;
		DataTypeManager dataTypeManager = desiredProgram.getDataTypeManager();

		signatureSource = SourceType.valueOf(strings.remove()); // Signature Source
		isInline = Boolean.parseBoolean(strings.remove()); // Inline Flag
		hasNoReturn = Boolean.parseBoolean(strings.remove()); // NoReturn Flag
		callingConventionName = strings.remove(); // Calling Convention Name
		callFixup = strings.remove(); // Call Fixup
		if (callFixup.equals("none")) {
			callFixup = null;
		}

		originalName = strings.remove(); // Original Function Name
		hasCustomStorage = Boolean.parseBoolean(strings.remove()); // Custom Storage Flag
		String returnTypeID = strings.remove(); // Return DataType ID with optional MAKE_POINTER_PREFIX
		String returnStorage = strings.remove(); // Return Storage
		returnInfo = new ParameterInfo(returnTypeID, dataTypeManager, Parameter.RETURN_NAME,
			returnStorage, SourceType.DEFAULT, null);

		String storageString = strings.remove(); // Parameter Storage		
		StringTokenizer storageTokenizer =
			new StringTokenizer(storageString, PARAMETER_STORAGE_DELIMITER);
		storageTokenizer.nextToken(); // ignore param count; not used
		List<String> parameterStorage = new ArrayList<>();
		while (storageTokenizer.hasMoreTokens()) {
			parameterStorage.add(storageTokenizer.nextToken());
		}

		hasVarargs = Boolean.parseBoolean(strings.remove()); // VarArgs Flag
		isThisCall = Boolean.parseBoolean(strings.remove()); // "This" Calling Convention Flag

		while (!strings.isEmpty()) {
			String paramInfoString = strings.remove();
			StringTokenizer paramTokenizer =
				new StringTokenizer(paramInfoString, PARAMETER_INFO_DELIMITER);
			String dtId = paramTokenizer.nextToken();
			String name = paramTokenizer.nextToken();
			if (StringUtils.isBlank(name)) {
				name = null;
			}

			String sourceAsName = paramTokenizer.nextToken();
			SourceType source = SourceType.valueOf(sourceAsName);
			String comment = null;
			try {
				comment = paramTokenizer.nextToken();
			}
			catch (NoSuchElementException e) {
				// Do nothing. There isn't a comment.
			}

			if (StringUtils.isBlank(comment)) {
				comment = null;
			}
			String decodedComment = decodeString(comment);
			String storage = null;
			int index = parameterInfos.size();
			if (parameterStorage.size() > index) {
				storage = parameterStorage.get(index);
			}

			parameterInfos.add(new ParameterInfo(dtId, dataTypeManager, name, storage, source,
				decodedComment));
		}
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

		if (!callingConventionName.equals(other.callingConventionName)) {
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

	public boolean isSameFunctionSignature(Function function) {
		return equals(new FunctionSignatureStringable(function));
	}

	/**
	 * Returns true if the signature is applied
	 * 
	 * @param destFunction the function whose signature we are setting.
	 * @param markupOptions the options indicate what parts of the function signature to apply.
	 * @param forceApply true indicates that the function signature should be applied even if the
	 * function signature, return type, parameter data type or parameter name options are set
	 * to "do not apply".
	 * @return true if the signature is applied
	 * @throws VersionTrackingApplyException if all desired parts of the function signature couldn't be applied.
	 */
	public boolean applyFunctionSignature(Function destFunction,
			ToolOptions markupOptions, boolean forceApply) throws VersionTrackingApplyException {

		if (doesParamCountMismatchPreventApply(destFunction, markupOptions)) {
			Msg.debug(this, "Number of parameters differs so function signature not applied at " +
				destFunction.getEntryPoint() + ".");
			return false;
		}

		applyInline(destFunction, isInline, markupOptions);
		applyNoReturn(destFunction, hasNoReturn, markupOptions);

		applyParameterTypes(destFunction, markupOptions, forceApply);

		boolean hasSrcVarArgs = hasVarargs;
		boolean hasDestVarArgs = destFunction.hasVarArgs();
		if (hasSrcVarArgs != hasDestVarArgs) {
			applyVarArgs(destFunction, hasSrcVarArgs, markupOptions);
		}

		applyCallFixup(destFunction, callFixup, markupOptions);

		if (forceApply) {
			forceParameterNames(destFunction);
		}
		else {
			int paramCount = destFunction.getParameterCount();
			applyParameterNames(destFunction, markupOptions, true, paramCount);
		}

		CommentChoices commentChoice =
			markupOptions.getEnum(PARAMETER_COMMENTS, DEFAULT_OPTION_FOR_PARAMETER_COMMENTS);
		replaceParameterComments(destFunction, commentChoice);

		return true;
	}

	private boolean doesParamCountMismatchPreventApply(Function destFunction,
			ToolOptions markupOptions) {

		VTMatchApplyChoices.FunctionSignatureChoices functionSignatureChoice = markupOptions
				.getEnum(VTOptionDefines.FUNCTION_SIGNATURE, DEFAULT_OPTION_FOR_FUNCTION_SIGNATURE);

		int paramCount = destFunction.getParameterCount();
		if (functionSignatureChoice == FunctionSignatureChoices.WHEN_SAME_PARAMETER_COUNT &&
			paramCount != parameterInfos.size()) {
			return true;
		}

		return false;
	}

	private void applyParameterTypes(Function destFunction, ToolOptions markupOptions,
			boolean forceApply) throws VersionTrackingApplyException {

		DataTypeCleaner dtCleaner = null;
		if (markupOptions.getBoolean(USE_EMPTY_COMPOSITES,
			// The user would like to create empty structures when creating data types
			DEFAULT_OPTION_FOR_USE_EMPTY_STRUCTURES)) {
			ProgramBasedDataTypeManager destDtm = destFunction.getProgram().getDataTypeManager();
			dtCleaner = new DataTypeCleaner(destDtm, false);
		}

		try {

			String conventionName = getCallingConvention(destFunction, markupOptions);
			boolean useCustomStorage = false;
			boolean sameLanguage =
				FunctionUtility.isSameLanguageAndCompilerSpec(destFunction.getProgram(), program);

			// if source program has custom storage and both programs have same language then
			// set the useCustomStorage flag to enable using custom storage in destination program
			if (sameLanguage && hasCustomStorage) {
				useCustomStorage = true;
			}

			Parameter returnParam =
				getReturnParameter(destFunction, markupOptions, forceApply, useCustomStorage,
					dtCleaner);

			List<Parameter> newParams =
				getParameters(destFunction, markupOptions, forceApply, useCustomStorage,
					dtCleaner);

			FunctionUpdateType updateType = useCustomStorage ? FunctionUpdateType.CUSTOM_STORAGE
					: FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS;
			destFunction.updateFunction(conventionName, returnParam, newParams, updateType,
				true, signatureSource);

			maybeCopyClassStructure(newParams, destFunction, markupOptions, dtCleaner);

			if (forceApply) {
				// must force signatureSource if precedence has been lowered
				destFunction.setSignatureSource(signatureSource);
			}
		}
		catch (DuplicateNameException | InvalidInputException e) {
			throw new VersionTrackingApplyException(e.getMessage(), e);
		}
		finally {
			if (dtCleaner != null) {
				dtCleaner.close();
			}
		}
	}

	/*
	 * Method to determine if a copy is needed of the source class struct to the destination program
	 * and if so, does the copy
	 */
	private void maybeCopyClassStructure(List<Parameter> newParams, Function destFunction,
			ToolOptions markupOptions, DataTypeCleaner dtCleaner) {

		if (newParams.isEmpty()) {
			return;
		}

		VTMatchApplyChoices.ParameterDataTypeChoices applyChoice =
			markupOptions.getEnum(VTOptionDefines.PARAMETER_DATA_TYPES,
				DEFAULT_OPTION_FOR_PARAMETER_DATA_TYPES);
		if (applyChoice == EXCLUDE) {
			return;
		}

		// This method is only meant to handle the case where there are auto this params.  Other 
		// mechanisms handle custom storage case already.
		if (destFunction.hasCustomVariableStorage()) {
			return;
		}

		//
		// Check to see if the newParams includes a this param and if so resolve the class data type
		// in the destination program to make sure the class structure gets copied to the 
		// destination program.
		// 

		// if source function is not a 'thiscall' then no class structure to copy
		if (!callingConventionName.equals(CompilerSpec.CALLING_CONVENTION_thiscall)) {
			return;
		}

		// if newParams does not have a this param then no copy needed
		Parameter destParam1 = newParams.get(0);
		String destParam1Name = destParam1.getName();
		if (!destParam1Name.equals("this")) {
			return;
		}

		// Verify the source this param is a pointer to a structure
		ParameterInfo sourceParam1 = parameterInfos.get(0);
		DataType srcClassDt = getPointedToDataType(sourceParam1.dataType);
		if (!isStructure(srcClassDt)) {
			return;
		}

		// Verify the destination this param is a pointer to a structure
		DataType paramDt = destParam1.getDataType();
		DataType destClassDt = getPointedToDataType(paramDt);
		if (!isStructure(destClassDt)) {
			return;
		}

		// If we get this far, then assume both the new destination and source this 
		// data types are pointers to class structures.
		// 
		// NOTE: we need check to see if the current function namespace is already 
		// the same as the assumed new destination this structure name which would indicate that 
		// the function already was in the same class and so we still need to do the resolve to make
		// sure that the structure contents get resolved according to the parameter replace options
		VTMatchApplyChoices.FunctionNameChoices functionNameChoice =
			markupOptions.getEnum(VTOptionDefines.FUNCTION_NAME, DEFAULT_OPTION_FOR_FUNCTION_NAME);
		Symbol functionSymbol = destFunction.getSymbol();
		String currentDestNamespace = functionSymbol.getParentNamespace().getName();
		String newDestnClassName = destClassDt.getName();
		if (functionNameChoice == FunctionNameChoices.EXCLUDE &&
			!currentDestNamespace.equals(newDestnClassName)) {

			// This check is odd.  I suppose we are trying to handle the case where the name was not
			// changed, but the namespace was updated.  In that case, we only need to copy the class
			// if the function was moved into a class namespace.  If the namespace names do not 
			// match, then that copy didn't happen.
			return;
		}

		// Use the source path get the same named structure in the destination data type manager
		ProgramBasedDataTypeManager destDtm = destFunction.getProgram().getDataTypeManager();
		String srcClassPath = srcClassDt.getPathName();
		DataType existingDestDt = destDtm.getDataType(srcClassPath);
		if (!shouldCopyClassStructure(applyChoice, existingDestDt)) {
			return;
		}

		// Use the original data type to get the struct *
		DataType dt = sourceParam1.dataType;
		if (dtCleaner != null) {
			// resolve an empty composite
			dt = dtCleaner.clean(dt);
		}

		// resolve the full data type
		destDtm.resolve(dt,
			DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);

		warnAboutClassConflicts(destFunction, destClassDt, srcClassPath);
	}

	private void warnAboutClassConflicts(Function toFunction, DataType newDestClassDt,
			String srcClassPath) {

		// Check to see if the resolve probably updated the function's auto this param datatype.
		// It might not have if there was a .conflict created during the resolve or if the
		// source and destination data types were in different folders or if one program
		// has the preferred root data type manager folder set and the other doesn't.
		// Not sure there is a way to tell this info since I don't know which the decompiler will
		// pick at this point because nothing has been applied yet.
		ProgramBasedDataTypeManager destDtm = toFunction.getProgram().getDataTypeManager();
		DataType destDtConflict = destDtm.getDataType(srcClassPath + ".conflict");
		if (destDtConflict != null) {
			Msg.debug(this, "Copied" + newDestClassDt.getPathName() +
				" to the destination program but a .conflict was created due to an existing " +
				"non-empty structure with that same path and name.");
		}

		// get the original toFunction this param if there was one and get it's path
		// if the new path is different then spit out warming too
		if (toFunction.getParameterCount() == 0) {
			return;
		}

		Parameter existingDestParam1 = toFunction.getParameter(0);
		if (!existingDestParam1.getName().equals("this")) {
			return;
		}

		DataType pointedToDt = getPointedToDataType(existingDestParam1.getDataType());
		if (pointedToDt == null) {
			return;
		}

		if (!pointedToDt.getName().equals(newDestClassDt.getName())) {
			return;
		}

		String existingClassPath = pointedToDt.getPathName();
		if (existingClassPath.equals(srcClassPath)) {
			return; // message already printed with conflict check above
		}

		//@formatter:off
		String message = """
			Class structure copied to '%s' which is different than the existing class structure \
			path '%s'. The decompiler will first check for one in the Preferred Class Root Folder \
			(if one has been set) otherwise it will use the first one it finds.
			""".formatted(srcClassPath, existingClassPath);
		//@formatter:on
		Msg.debug(this, message);
	}

	private boolean shouldCopyClassStructure(ParameterDataTypeChoices applyChoice,
			DataType existingDestDt) {

		if (applyChoice == REPLACE) {
			return true; // always replace
		}

		if (existingDestDt == null) {
			return true; // no class; need to copy
		}

		boolean onlyReplaceUndefineds = applyChoice == REPLACE_UNDEFINED_DATA_TYPES_ONLY;
		return existingDestDt.isNotYetDefined() && onlyReplaceUndefineds;
	}

	private boolean isStructure(DataType dataType) {

		if (dataType instanceof Structure) {
			return true;
		}

		if (dataType instanceof StructureDataType) {
			return true;
		}

		return false;

	}

	private DataType getPointedToDataType(DataType dataType) {
		if (dataType instanceof PointerDataType pointer) {
			return pointer.getDataType();
		}
		return null;
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

	private Parameter getReturnParameter(Function destFunction, ToolOptions markupOptions,
			boolean forceApply, boolean useCustomStorage, DataTypeCleaner dtCleaner)
			throws InvalidInputException {

		Parameter returnParam = destFunction.getReturn();
		ParameterDataTypeChoices returnTypeChoice =
			markupOptions.getEnum(FUNCTION_RETURN_TYPE, DEFAULT_OPTION_FOR_FUNCTION_RETURN_TYPE);
		if (returnTypeChoice == ParameterDataTypeChoices.EXCLUDE) {
			return returnParam; // Not replacing return type.
		}

		DataType toReturnType = destFunction.getReturnType();
		DataType fromReturnType = returnInfo.dataType;
		boolean isFromDefault = fromReturnType == DataType.DEFAULT;
		boolean isToDefault = toReturnType == DataType.DEFAULT;
		boolean isToUndefined = Undefined.isUndefined(getBaseDataType(toReturnType));

		boolean onlyReplaceUndefineds =
			returnTypeChoice == ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY;
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

		Program destProgram = destFunction.getProgram();
		VariableStorage storage = VariableStorage.UNASSIGNED_STORAGE;
		if (useCustomStorage && returnInfo.storage != null) {
			storage = VariableStorage.deserialize(destProgram, returnInfo.storage);
		}

		// Update the type if the user prefers empty composites
		if (dtCleaner != null) {
			returnType = dtCleaner.clean(returnType);
		}

		return new ReturnParameterImpl(returnType, storage, destProgram);
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
			if (FunctionUtility.isSameLanguageAndCompilerSpec(toFunction.getProgram(), program)) {
				toFunction.setCallFixup(fromFunctionCallFixup);
			}
		}
	}

	private String getCallingConvention(Function toFunction, ToolOptions markupOptions) {

		boolean isFromUnknownCallingConvention =
			CompilerSpec.isUnknownCallingConvention(callingConventionName);
		CallingConventionChoices callingConventionChoice =
			markupOptions.getEnum(CALLING_CONVENTION, DEFAULT_OPTION_FOR_CALLING_CONVENTION);
		String toCallingConventionName = toFunction.getCallingConventionName();
		if (Objects.equals(callingConventionName, toCallingConventionName)) {
			return callingConventionName;
		}

		Program toProgram = toFunction.getProgram();
		switch (callingConventionChoice) {
			case SAME_LANGUAGE:
				if (FunctionUtility.isSameLanguageAndCompilerSpec(program, toProgram)) {
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
		return callingConvention != null;
	}

	private List<Parameter> getParameters(Function toFunction, ToolOptions markupOptions,
			boolean forceApply, boolean useCustomStorage, DataTypeCleaner dtCleaner)
			throws InvalidInputException {

		// See what options the user has specified when applying parameter names.
		VTMatchApplyChoices.ParameterDataTypeChoices parameterDataTypesChoice =
			markupOptions.getEnum(VTOptionDefines.PARAMETER_DATA_TYPES,
				DEFAULT_OPTION_FOR_PARAMETER_DATA_TYPES);

		boolean onlyReplaceUndefineds =
			parameterDataTypesChoice == ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY;

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

			// Update the type if the user prefers empty composites
			if (dtCleaner != null) {
				dataType = dtCleaner.clean(dataType);
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

	/**
	 * If the given data type is a pointer, get the "pointed to" data type
	 * @param dataType the given data type
	 * @return if not a pointer, just return the same dataType, if a pointer, return the 
	 * "pointed to" data type
	 */
	private DataType getBaseDataType(DataType dataType) {

		if (dataType instanceof Pointer) {
			Pointer pointer = (Pointer) dataType;
			dataType = pointer.getDataType();
		}
		return dataType;
	}

	private DataType getHighestPriorityDataType(DataType fromDataType, DataType toDataType,
			boolean onlyReplaceUndefineds) {
		// Priority from highest to lowest is Defined, Undefined with size, Default.
		boolean fromIsDefault = fromDataType == DataType.DEFAULT;
		boolean toIsDefault = toDataType == DataType.DEFAULT;
		boolean fromIsUndefined = Undefined.isUndefined(getBaseDataType(fromDataType));
		boolean toIsUndefined = Undefined.isUndefined(getBaseDataType(toDataType));
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
	 * Applies the given parameter names
	 * 
	 * @param destFunction the function whose parameter names we are setting.
	 * @param markupOptions the options
	 * @param doNotReplaceWithDefaultNames flag indicating whether or not a parameter name can be
	 * replaced with a default name.
	 * @param originalDestParamCount original number of parameters in toFunction
	 * @throws VersionTrackingApplyException if there is any exception applying a name
	 */
	public void applyParameterNames(Function destFunction, ToolOptions markupOptions,
			boolean doNotReplaceWithDefaultNames, int originalDestParamCount)
			throws VersionTrackingApplyException {

		// See what options the user has specified when applying parameter names.
		VTMatchApplyChoices.SourcePriorityChoices parameterNamesChoice = markupOptions
				.getEnum(VTOptionDefines.PARAMETER_NAMES, DEFAULT_OPTION_FOR_PARAMETER_NAMES);
		VTMatchApplyChoices.HighestSourcePriorityChoices priorityChoice =
			markupOptions.getEnum(VTOptionDefines.HIGHEST_NAME_PRIORITY,
				DEFAULT_OPTION_FOR_HIGHEST_NAME_PRIORITY);
		boolean replaceSamePriorityNames =
			markupOptions.getBoolean(PARAMETER_NAMES_REPLACE_IF_SAME_PRIORITY,
				DEFAULT_OPTION_FOR_PARAMETER_NAMES_REPLACE_IF_SAME_PRIORITY);

		int fromParameterCount = parameterInfos.size();
		int minParameterCount = Math.min(fromParameterCount, originalDestParamCount);
		boolean duplicateNameOccurred =
			tryToSetNames(destFunction, doNotReplaceWithDefaultNames, parameterNamesChoice,
				priorityChoice, replaceSamePriorityNames, minParameterCount);

		// If a duplicate name was created, then try applying again to see if it can now be set
		// to the desired name. A duplicate may have occurred due to changing order of parameters.
		if (duplicateNameOccurred) {
			tryToSetNames(destFunction, doNotReplaceWithDefaultNames, parameterNamesChoice,
				priorityChoice, replaceSamePriorityNames, minParameterCount);
		}

	}

	private boolean tryToSetNames(Function toFunction, boolean doNotReplaceWithDefaultNames,
			VTMatchApplyChoices.SourcePriorityChoices parameterNamesChoice,
			VTMatchApplyChoices.HighestSourcePriorityChoices highestPriorityChoice,
			boolean replaceSamePriorityNames, int minParameterCount)
			throws VersionTrackingApplyException {

		boolean duplicateName = false;
		int n = parameterInfos.size();
		for (int i = 0; i < n; i++) {
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
			if (Objects.equals(fromName, toName)) {
				continue;
			}

			if (i < minParameterCount) {
				switch (parameterNamesChoice) {
					case PRIORITY_REPLACE:
						if (highestPriorityChoice == HighestSourcePriorityChoices.IMPORT_PRIORITY_HIGHEST) {
							// Import, User, Analysis, Default.
							if (!isFirstHigherPriorityForImports(fromSource, toSource,
								replaceSamePriorityNames)) {
								continue;
							}
						}
						else {
							// User, Import, Analysis, Default.
							if (!isFirstHigherPriorityWhenForUser(fromSource, toSource,
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

			duplicateName = setName(toFunction, toParameter, fromName, fromSource);
		}
		return duplicateName;
	}

	private boolean setName(Function function, Parameter parameter, String name,
			SourceType source) throws VersionTrackingApplyException {

		try {
			parameter.setName(name, source);
			return false;
		}
		catch (DuplicateNameException e) {
			Program p = function.getProgram();
			SymbolTable st = p.getSymbolTable();
			String uniqueName = getUniqueParameterName(st, function, name);
			try {
				parameter.setName(uniqueName, source);
				return true;
			}
			catch (DuplicateNameException | InvalidInputException e1) {
				// shouldn't happen
				throw new VersionTrackingApplyException(e1.getMessage(), e1);
			}
		}
		catch (InvalidInputException e) {
			throw new VersionTrackingApplyException(e.getMessage(), e);
		}
	}

	/**
	 * Uses this stringable's parameter info to set the name and source types for the specified
	 * function. Even default names from the parameter info will replace a defined parameter
	 * name in the function.
	 * @param toFunction the function whose parameter names are to be changed using the names
	 * from this stringable.
	 * @throws VersionTrackingApplyException if there is any exception applying the names
	 */
	private void forceParameterNames(Function toFunction) throws VersionTrackingApplyException {

		boolean duplicateNameOccurred = tryToForceNames(toFunction);
		if (duplicateNameOccurred) {
			// If a duplicate name was created, then try applying again to see if it can now be set
			// to the desired name. A duplicate may have occurred due to changing order of parameters.
			tryToForceNames(toFunction);
		}
	}

	private boolean tryToForceNames(Function toFunction) throws VersionTrackingApplyException {
		boolean duplicateName = false;
		for (int i = 0; i < parameterInfos.size(); i++) {
			ParameterInfo parameterInfo = parameterInfos.get(i);
			String fromName = parameterInfo.name;
			SourceType fromSource = parameterInfo.source;
			Parameter toParameter = toFunction.getParameter(i);
			if (toParameter.isAutoParameter()) {
				continue;
			}

			SourceType toSource = toParameter.getSource();
			String toName = (toSource != SourceType.DEFAULT) ? toParameter.getName() : null;
			if (Objects.equals(fromName, toName)) {
				continue;
			}

			duplicateName = setName(toFunction, toParameter, fromName, fromSource);
		}
		return duplicateName;
	}

	private boolean isFirstHigherPriorityWhenForUser(SourceType first, SourceType second,
			boolean replaceSamePriorityNames) {
		if (first == SourceType.DEFAULT) {
			return false;
		}
		if (first == second) {
			return replaceSamePriorityNames;
		}
		return first.isHigherPriorityThan(second);
	}

	private boolean isFirstHigherPriorityForImports(SourceType first, SourceType second,
			boolean replaceSamePriorityNames) {
		if (first == SourceType.DEFAULT) {
			return false;
		}
		if (first == second) {
			return replaceSamePriorityNames;
		}
		// Force IMPORTED to have highest priority
		if (first == SourceType.IMPORTED) {
			return true;
		}
		else if (second == SourceType.IMPORTED) {
			return false;
		}
		return first.isHigherPriorityThan(second);
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
			if (Objects.equals(fromComment, toComment)) {
				continue;
			}

			if (commentChoice == CommentChoices.APPEND_TO_EXISTING) {
				String mergedComment = StringUtilities.mergeStrings(toComment, fromComment);
				if (StringUtils.isBlank(mergedComment)) {
					mergedComment = null;
				}

				if (!Objects.equals(mergedComment, toComment)) {
					toParameter.setComment(mergedComment);
				}
			}

			if (commentChoice == CommentChoices.OVERWRITE_EXISTING) {
				if (StringUtils.isBlank(fromComment)) {
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

		private ParameterInfo(DataType dataType, String name, String storage, SourceType source,
				String comment) {
			this.dataType = dataType;
			this.name = name;
			this.storage = storage;
			this.source = source;
			this.comment = StringUtils.isBlank(comment) ? null : comment;
		}

		private ParameterInfo(String serializedDtId, DataTypeManager dtm, String name,
				String storage, SourceType source, String comment) {

			this.dataType = getDt(dtm, serializedDtId);
			this.name = name;
			this.storage = storage;
			this.source = source;
			this.comment = StringUtils.isBlank(comment) ? null : comment;
		}

		private DataType getDt(DataTypeManager dtm, String dtIdString) {
			long dtId = -1;
			boolean makePtr = false;
			if (!StringUtils.isBlank(dtIdString)) {
				if (dtIdString.startsWith(MAKE_POINTER_PREFIX)) {
					makePtr = true;
					dtIdString = dtIdString.substring(MAKE_POINTER_PREFIX.length());
				}
				dtId = Long.parseLong(dtIdString);
			}

			DataType dt = dtm.getDataType(dtId);
			if (makePtr) {
				dt = new PointerDataType(dt, dtm);
			}
			return dt;
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
			int count = 0;
			while (symbolTable.getVariableSymbol(name, function) != null) {
				name = baseName + (++count);
			}
		}
		return name;
	}
}
