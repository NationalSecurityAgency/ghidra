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
package ghidra.program.model.listing;

import java.util.List;
import java.util.Set;

import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Interface to define methods available on a function. Functions have a single entry point.
 */
public interface Function extends Namespace {

	public static final String DEFAULT_PARAM_PREFIX = "param_";
	public static final String THIS_PARAM_NAME = AutoParameterType.THIS.getDisplayName();
	public static final String RETURN_PTR_PARAM_NAME =
		AutoParameterType.RETURN_STORAGE_PTR.getDisplayName();
	public static final int DEFAULT_PARAM_PREFIX_LEN = DEFAULT_PARAM_PREFIX.length();
	public static final String DEFAULT_LOCAL_PREFIX = "local_";
	public static final String DEFAULT_LOCAL_RESERVED_PREFIX = "local_res";
	public static final String DEFAULT_LOCAL_TEMP_PREFIX = "temp_";
	public static final int DEFAULT_LOCAL_PREFIX_LEN = DEFAULT_LOCAL_PREFIX.length();
	public static final String UNKNOWN_CALLING_CONVENTION_STRING = "unknown";
	public static final String DEFAULT_CALLING_CONVENTION_STRING = "default";
	public static final String INLINE = "inline";
	public static final String NORETURN = "noreturn";
	public static final String THUNK = "thunk";

	public enum FunctionUpdateType {
		/**
		 * All parameters and return have been specified with their storage.
		 */
		CUSTOM_STORAGE,
		/**
		 * The formal signature parameters and return have been specified without storage.
		 * Storage will be computed.  Any use of the reserved names 'this' and 
		 * '__return_storage_ptr__' will be stripped before considering the injection
		 * of these parameters.
		 */
		DYNAMIC_STORAGE_FORMAL_PARAMS,
		/**
		 * 
		 */
		/**
		 * All parameters and return have been specified without storage.
		 * Storage will be computed.  Any use of the reserved names 'this' and 
		 * '__return_storage_ptr__' will be stripped before considering the injection
		 * of these parameters.  In addition, if the calling convention is '__thiscall'
		 * if the 'this' parameter was not identified by name, the first parameter will
		 * be assumed the 'this' parameter if its name is a default name and it has
		 * the size of a pointer.
		 */
		DYNAMIC_STORAGE_ALL_PARAMS;
	}

	/**
	 * Default Stack depth for a function.
	 */
	public final static int UNKNOWN_STACK_DEPTH_CHANGE = Integer.MAX_VALUE;
	public final static int INVALID_STACK_DEPTH_CHANGE = Integer.MAX_VALUE - 1;

	/**
	 * Get the name of this function.
	 *
	 * @return the functions name
	 */
	@Override
	public String getName();

	/**  
	 * Set the name of this function.
	 * @param name the new name of the function
	 * @param source the source of this function name
	 * @throws DuplicateNameException if the name is used by some other symbol
	 * @throws InvalidInputException if the name is not a valid function name.
	 */
	public void setName(String name, SourceType source)
			throws DuplicateNameException, InvalidInputException;

	/**
	 * Set the named call-fixup for this function.
	 * @param name name of call-fixup specified by compiler spec.  A null
	 * value will clear the current setting.
	 */
	public void setCallFixup(String name);

	/**
	 * Returns the current call-fixup name set on this instruction or null if one has not been set
	 * @return the name
	 */
	public String getCallFixup();

	/**
	 * Get the program containing this function.
	 *
	 * @return the program
	 */
	public Program getProgram();

	/**
	 * Get the comment for this function.
	 * @return the comment for this function
	 */
	public String getComment();

	/**
	 * Returns the function (same as plate) comment as an array of strings where
	 * each item in the array is a line of text in the comment.
	 * @return the comments
	 */
	public String[] getCommentAsArray();

	/**
	 * Set the comment for this function.
	 * @param comment the string to set as the comment.
	 */
	public void setComment(String comment);

	/**
	 * Returns the repeatable comment for this function.
	 * A repeatable comment is a comment that will appear
	 * at locations that 'call' this function.
	 * @return the repeatable comment for this function
	 */
	public String getRepeatableComment();

	/**
	 * Returns the repeatable comment as an array of strings.
	 * @return the repeatable comment as an array of strings
	 */
	public String[] getRepeatableCommentAsArray();

	/**
	 * Set the repeatable comment for this function.
	 * @param comment the string to set as the repeatable comment.
	 */
	public void setRepeatableComment(String comment);

	/**
	 * Get the entry point for this function.
	 * Functions may only have ONE entry point.
	 *
	 * @return the entry point
	 */
	public Address getEntryPoint();

	/**
	 * Get the Function's return type.
	 * A null return value indicates the functions return type has never been set.
	 *
	 * @return the DataType that this function returns.
	 */
	public DataType getReturnType();

	/**
	 * Set the function's return type.
	 * @param type the dataType that will define this functions return type.
	 * @param source TODO
	 * @throws InvalidInputException if data type is not a fixed length.
	 */
	public void setReturnType(DataType type, SourceType source) throws InvalidInputException;

	/**
	 * Get the Function's return type/storage represented by a Parameter 
	 * object.  The parameter's ordinal value will be equal to
	 * Parameter.RETURN_ORIDINAL.
	 * @return return data-type/storage
	 */
	public Parameter getReturn();

	/**
	 * Set the return data-type and storage.
	 * 
	 * <p>NOTE: The storage and source are ignored if the function does not have custom storage 
	 * enabled.
	 * 
	 * @param type the data type
	 * @param storage the storage
	 * @param source source to be combined with the overall signature source. 
	 * @throws InvalidInputException if data type is not a fixed length or storage is improperly 
	 *         sized
	 */
	public void setReturn(DataType type, VariableStorage storage, SourceType source)
			throws InvalidInputException;

	/**
	 * Get the function's effective signature.
	 * This is equivalent to invoking <code>getSignature(false)</code> where auto-params and 
	 * forced-indirect types will be reflected in the signature if present.
	 * <br><br>WARNING! It is important to note that the calling convention may not be properly retained 
	 * by the returned signature object if a non-generic calling convention is used by this function as 
	 * defined by the program's compiler specification.
	 * @return the function's signature
	 */
	public FunctionSignature getSignature();

	/**
	 * Get the function's signature.
	 * <br><br>WARNING! It is important to note that the calling convention may not be properly 
	 * retained by the returned signature object if a non-generic calling convention is used by 
	 * this function as defined by the program's compiler specification.
	 * 
	 * @param formalSignature if true only original raw types will be retained and 
	 * auto-params discarded (e.g., this, __return_storage_ptr__, etc.) within the returned 
	 * signature.  If false, the effective signature will be returned where forced indirect 
	 * and auto-params are reflected in the signature.  This option has no affect if the specified 
	 * function has custom storage enabled.
	 * @return the function's signature
	 */
	public FunctionSignature getSignature(boolean formalSignature);

	/**
	 * Return a string representation of the function signature
	 * 
	 * @param formalSignature if true only original raw return/parameter types will be retained and 
	 * auto-params discarded (e.g., this, __return_storage_ptr__, etc.) within the returned 
	 * signature.  If false, the effective signature will be returned where forced indirect 
	 * and auto-params are reflected in the signature.  This option has no affect if the specified 
	 * function has custom storage enabled.
	 * @param includeCallingConvention if true prototype will include call convention
	 * declaration if known.
	 * @return the prototype
	 */
	public String getPrototypeString(boolean formalSignature, boolean includeCallingConvention);

	/**
	 * Returns the source type for the overall signature excluding function name and parameter names 
	 * whose source is carried by the corresponding symbol.
	 * @return the overall SourceType of the function signature;
	 */
	public SourceType getSignatureSource();

	/**
	 * Set the source type for the overall signature excluding function name and parameter names 
	 * whose source is carried by the corresponding symbol.
	 * @param signatureSource function signature source type
	 */
	public void setSignatureSource(SourceType signatureSource);

	/**
	 * Get the stack frame for this function.
	 * NOTE: Use of the stack frame must be avoided during upgrade activity since
	 * the compiler spec may not be known (i.e., due to language upgrade process).
	 * @return this functions stack frame
	 */
	public StackFrame getStackFrame();

	/**
	 * Get the change in the stack pointer resulting from calling
	 *  this function.
	 * 
	 * @return int the change in bytes to the stack pointer
	 */
	public int getStackPurgeSize();

	/**
	 * Return all {@link FunctionTag} objects associated with this function.
	 * 
	 * @return set of tag names
	 */
	public Set<FunctionTag> getTags();

	/**
	 * Adds the tag with the given name to this function; if one does
	 * not exist, one is created.
	 * 
	 * @param name the tag name to add
	 * @return true if the tag was successfully added
	 */
	public boolean addTag(String name);

	/**
	 * Removes the given tag from this function.
	 * 
	 * @param name the tag name to be removed.
	 */
	public void removeTag(String name);

	/**
	 * Set the change in the stack pointer resulting from calling
	 * this function.
	 * 
	 * @param purgeSize the change in bytes to the stack pointer
	 */
	public void setStackPurgeSize(int purgeSize);

	/**
	 * check if stack purge size is valid.
	 * 
	 * @return true if the stack depth is valid
	 */
	public boolean isStackPurgeSizeValid();

	/**
	 * Adds the given variable to the end of the parameters list.  The variable storage specified
	 * for the new parameter will be ignored if custom storage mode is not enabled.
	 * The {@link VariableUtilities#checkVariableConflict(Function, Variable, VariableStorage, boolean)} 
	 * method may be used to check and remove conflicting variables which already exist in the function.
	 * @param var the variable to add as a new parameter.
	 * @param source the source of this parameter which will be applied to the parameter symbol and 
	 * overall function signature source.  If parameter has a null or default name a SourceType of DEFAULT
	 * will be applied to the parameter symbol.
	 * @return the Parameter object created.
	 * @throws DuplicateNameException if another variable(parameter or local) already
	 * exists in the function with that name.
	 * @throws InvalidInputException if data type is not a fixed length or variable name is invalid.
	 * @throws VariableSizeException if data type size is too large based upon storage constraints.
	 * @deprecated The use of this method is discouraged due to the potential injection of auto-parameters
	 * which are easily overlooked when considering parameter ordinal.  The function signature should generally be 
	 * adjusted with a single call to {@link #updateFunction(String, Variable, List, FunctionUpdateType, boolean, SourceType)}
	 */
	@Deprecated
	public Parameter addParameter(Variable var, SourceType source)
			throws DuplicateNameException, InvalidInputException;

	/**
	 * Inserts the given variable into the parameters list.  The variable storage specified
	 * for the new parameter will be ignored if custom storage mode is not enabled.
	 * The {@link VariableUtilities#checkVariableConflict(Function, Variable, VariableStorage, boolean)} 
	 * method may be used to check and remove conflicting variables which already exist in the function.
	 * @param ordinal the position with the parameters to insert to.  This ordinal must factor in the
	 * presence of auto-parameters which may be injected dynamically based upon calling convention and
	 * return data type.  Parameters may not be inserted befor an auto-parameter.
	 * @param var the variable to add as a new parameter.
	 * @param source the source of this parameter which will be applied to the parameter symbol and 
	 * overall function signature source.  If parameter has a null or default name a SourceType of DEFAULT
	 * will be applied to the parameter symbol.
	 * @return the Parameter object created.
	 * @throws DuplicateNameException if another variable(parameter or local) already
	 * exists in the function with that name.
	 * @throws InvalidInputException if data type is not a fixed length or variable name is invalid.
	 * @throws VariableSizeException if data type size is too large based upon storage constraints.
	 * @deprecated The use of this method is discouraged due to the potential injection of auto-parameters
	 * which are easily overlooked when considering parameter ordinal.  The function signature should generally be 
	 * adjusted with a single call to {@link #updateFunction(String, Variable, List, FunctionUpdateType, boolean, SourceType)}
	 */
	@Deprecated
	public Parameter insertParameter(int ordinal, Variable var, SourceType source)
			throws DuplicateNameException, InvalidInputException;

	/**
	 * Replace all current parameters with the given list of parameters.
	 * The {@link VariableUtilities#checkVariableConflict(Function, Variable, VariableStorage, boolean)} 
	 * method may be used to check and remove conflicting variables which already exist in the function.
	 * @param params the new set of parameters for the function.
	 * @param updateType function update type
	 * @param force if true any conflicting local parameters will be removed
	 * @param source the source of these parameters which will be applied to the parameter symbols and 
	 * overall function signature source.  If parameter names are null or a default name a SourceType of DEFAULT
	 * will be applied to the corresponding parameter symbol.
	 * @throws DuplicateNameException if another variable(parameter or local) already
	 * exists in the function with that name.
	 * @throws InvalidInputException if a parameter data type is not a fixed length or variable name is invalid.
	 * @throws VariableSizeException if a parameter data type size is too large based upon storage constraints
	 * or conflicts with another variable.
	 */
	public void replaceParameters(List<? extends Variable> params, FunctionUpdateType updateType,
			boolean force, SourceType source) throws DuplicateNameException, InvalidInputException;

	/**
	 * Replace all current parameters with the given list of parameters.
	 * The {@link VariableUtilities#checkVariableConflict(Function, Variable, VariableStorage, boolean)} 
	 * method may be used to check and remove conflicting variables which already exist in the function.
	 * @param updateType function update type
	 * @param force if true any conflicting local parameters will be removed
	 * @param source the source of these parameters which will be applied to the parameter symbols and 
	 * overall function signature source.  If parameter names are null or a default name a SourceType of DEFAULT
	 * will be applied to the corresponding parameter symbol.
	 * @param params the new parameters for the function.
	 * @throws DuplicateNameException if another variable(parameter or local) already
	 * exists in the function with that name.
	 * @throws InvalidInputException if a parameter data type is not a fixed length or variable name is invalid.
	 * @throws VariableSizeException if a parameter data type size is too large based upon storage constraints
	 * or conflicts with another variable.
	 */
	public void replaceParameters(FunctionUpdateType updateType, boolean force, SourceType source,
			Variable... params) throws DuplicateNameException, InvalidInputException;

	/**
	 * Replace all current parameters with the given list of parameters and optionally change the calling convention
	 * and function return.
	 * The {@link VariableUtilities#checkVariableConflict(Function, Variable, VariableStorage, boolean)} 
	 * method may be used to check and remove conflicting variables which already exist in the function.
	 * @param callingConvention updated calling convention name or null if no change is required
	 * @param returnValue return variable or null if no change required
	 * @param updateType function update type
	 * @param force if true any conflicting local parameters will be removed
	 * @param source the source of these parameters which will be applied to the parameter symbols and 
	 * overall function signature source.  If parameter names are null or a default name a SourceType of DEFAULT
	 * will be applied to the corresponding parameter symbol.
	 * @param newParams a variable number of parameters for the function.
	 * @throws DuplicateNameException if another variable(parameter or local) already
	 * exists in the function with that name.
	 * @throws InvalidInputException if a parameter data type is not a fixed length or variable name is invalid.
	 * @throws VariableSizeException if a parameter data type size is too large based upon storage constraints
	 * or conflicts with another variable.
	 */
	public void updateFunction(String callingConvention, Variable returnValue,
			FunctionUpdateType updateType, boolean force, SourceType source, Variable... newParams)
			throws DuplicateNameException, InvalidInputException;

	/**
	 * Replace all current parameters with the given list of parameters and optionally change the calling convention
	 * and function return.
	 * The {@link VariableUtilities#checkVariableConflict(Function, Variable, VariableStorage, boolean)} 
	 * method may be used to check and remove conflicting variables which already exist in the function.
	 * @param callingConvention updated calling convention name or null if no change is required
	 * @param returnVar return variable or null if no change required
	 * @param updateType function update type
	 * @param force if true any conflicting local parameters will be removed
	 * @param source the source of these parameters which will be applied to the parameter symbols and 
	 * overall function signature source.  If parameter names are null or a default name a SourceType of DEFAULT
	 * will be applied to the corresponding parameter symbol.
	 * @param newParams the list of new parameters for the function (required).
	 * @throws DuplicateNameException if another variable(parameter or local) already
	 * exists in the function with that name.
	 * @throws InvalidInputException if a parameter data type is not a fixed length or variable name is invalid.
	 * @throws VariableSizeException if a parameter data type size is too large based upon storage constraints
	 * or conflicts with another variable.
	 */
	public void updateFunction(String callingConvention, Variable returnVar,
			List<? extends Variable> newParams, FunctionUpdateType updateType, boolean force,
			SourceType source) throws DuplicateNameException, InvalidInputException;

	/**
	 * Returns the specified parameter including an auto-param at the specified ordinal.
	 * @param ordinal the index of the parameter to return.
	 * @return parameter or null if ordinal is out of range
	 */
	public Parameter getParameter(int ordinal);

	/**
	 * Remove the specified parameter.  Auto-parameters may not be removed but must be accounted 
	 * for in the specified ordinal.
	 * @param ordinal the index of the parameter to be removed.
	 * @deprecated The use of this method is discouraged.  The function signature should generally be 
	 * adjusted with a single call to {@link #updateFunction(String, Variable, List, FunctionUpdateType, boolean, SourceType)}
	 */
	@Deprecated
	public void removeParameter(int ordinal);

	/**
	 * Move the parameter which occupies the fromOrdinal position to the toOrdinal position.
	 * Parameters will be renumbered to reflect the new ordering.  Auto-parameters may not be 
	 * moved but must be accounted for in the specified ordinals.
	 * @param fromOrdinal from ordinal position using the current numbering
	 * @param toOrdinal the final position of the specified parameter
	 * @return parameter which was moved
	 * @throws InvalidInputException if either ordinal is invalid
	 * @deprecated The use of this method is discouraged.  The function signature should generally be 
	 * adjusted with a single call to {@link #updateFunction(String, Variable, List, FunctionUpdateType, boolean, SourceType)}
	 */
	@Deprecated
	public Parameter moveParameter(int fromOrdinal, int toOrdinal) throws InvalidInputException;

	/**
	 * Gets the total number of parameters for this function.  This number also includes any
	 * auto-parameters which may have been injected when dynamic parameter storage is used. 
	 * @return the total number of parameters
	 */
	public int getParameterCount();

	/**
	 * Gets the number of auto-parameters for this function also included in the total
	 * count provided by {@link #getParameterCount()}.  This number will always be 0 when
	 * custom parameter storage is used.
	 * @return the number of auto-parameters
	 */
	public int getAutoParameterCount();

	/**
	 * Get all function parameters
	 * @return all function parameters
	 */
	public Parameter[] getParameters();

	/**
	 * Get all function parameters which satisfy the specified filter
	 * @param filter variable filter or null for all parameters to be returned
	 * @return all function parameters which satisfy the specified filter
	 */
	public Parameter[] getParameters(VariableFilter filter);

	/**
	 * Get all local function variables
	 * @return all local function variables
	 */
	public Variable[] getLocalVariables();

	/**
	 * Get all local function variables which satisfy the specified filter
	 * @param filter variable filter or null for all local variables to be returned
	 * @return all function variables which satisfy the specified filter
	 */
	public Variable[] getLocalVariables(VariableFilter filter);

	/**
	 * Get all function variables which satisfy the specified filter
	 * @param filter variable filter or null for all variables to be returned
	 * @return all function variables which satisfy the specified filter
	 */
	public Variable[] getVariables(VariableFilter filter);

	/**
	 * Returns an array of all local and parameter variables
	 * @return the variables
	 */
	public Variable[] getAllVariables();

	/**
	 * Adds a local variable to the function.
	 * The {@link VariableUtilities#checkVariableConflict(Function, Variable, VariableStorage, boolean)} 
	 * method may be used to check and remove conflicting variables which already exist in the function.
	 * @param var the variable to add.
	 * @param source the source of this local variable
	 * @return the Variable added to the program.
	 * @throws DuplicateNameException if another local variable or parameter already
	 * has that name.
	 * @throws InvalidInputException if there is an error or conflict when resolving the variable 
	 */
	public Variable addLocalVariable(Variable var, SourceType source)
			throws DuplicateNameException, InvalidInputException;

	/**
	 * Removes the given variable from the function.
	 * @param var the variable to remove.
	 */
	public void removeVariable(Variable var);

	/**
	 * Set the new body for this function. The entry point must be contained
	 * in the new body.
	 * @param newBody address set to use as the body of this function
	 * @throws OverlappingFunctionException if the address set overlaps that
	 * of another function
	 */
	public void setBody(AddressSetView newBody) throws OverlappingFunctionException;

	/**
	 * Returns true if this function has a variable argument list (VarArgs)
	 * @return true if this function has a variable argument list (VarArgs)
	 */
	public boolean hasVarArgs();

	/**
	 * Set whether parameters can be passed as a VarArg (variable argument list)
	 * 
	 * @param hasVarArgs true if this function has a variable argument list 
	 *        (e.g.,  printf(fmt, ...)).
	 */
	public void setVarArgs(boolean hasVarArgs);

	/**
	 * @return true if this is an inline function.
	 */
	public boolean isInline();

	/**
	 * Sets whether or not this function is inline.
	 * 
	 * @param isInline true if this is an inline function.
	 */
	public void setInline(boolean isInline);

	/**
	 * @return true if this function does not return.
	 */
	public boolean hasNoReturn();

	/**
	 * Set whether or not this function has a return.
	 * 
	 * @param hasNoReturn true if this function does not return.
	 */
	public void setNoReturn(boolean hasNoReturn);

	/**
	 * @return true if function parameters utilize custom variable storage.
	 */
	public boolean hasCustomVariableStorage();

	/**
	 * Set whether or not this function uses custom variable storage
	 * @param hasCustomVariableStorage true if this function uses custom storage
	 */
	public void setCustomVariableStorage(boolean hasCustomVariableStorage);

	/**
	 * Gets the calling convention prototype model for this function.
	 * 
	 * @return the prototype model of the function's current calling convention or null.
	 */
	public PrototypeModel getCallingConvention();

	/**
	 * Gets the calling convention's name for this function.
	 * 
	 * @return the name of the calling convention 
	 * or Function.DEFAULT_CALLING_CONVENTION_STRING 
	 * (i.e. "default", if the calling convention has been set to the default for this function)
	 * or Function.UNKNOWN_CALLING_CONVENTION_STRING 
	 * (i.e. "unknown", if no calling convention is specified for this function).
	 */
	public String getCallingConventionName();

	/**
	 * Gets the name of the default calling convention.
	 * <br>Note: The name in the PrototypeModel of the default calling convention may be null.
	 * 
	 * @return the name of the default calling convention.
	 */
	public String getDefaultCallingConventionName();

	/**
	 * Sets the calling convention for this function to the named calling convention.
	 * @param name the name of the calling convention. "unknown" and "default" are reserved names
	 * that can also be used here. 
	 * <br>Null or Function.UNKNOWN_CALLING_CONVENTION_STRING sets this function to not have a 
	 * calling convention (i.e. unknown).
	 * <br>Function.DEFAULT_CALLING_CONVENTION_STRING sets this function to use the default calling 
	 * convention. (i.e. default)
	 * @throws InvalidInputException if the specified name is not a recognized calling convention name.
	 */
	public void setCallingConvention(String name) throws InvalidInputException;

	/**
	 * @return true if this function is a Thunk and has a referenced Thunked Function.
	 * @see #getThunkedFunction(boolean)
	 */
	public boolean isThunk();

	/**
	 * If this function is a Thunk, this method returns the referenced function.
	 * @param recursive if true and the thunked-function is a thunk itself, the returned 
	 * thunked-function will be the final thunked-function which will never be a thunk.
	 * @return function referenced by this Thunk Function or null if this is not a Thunk
	 * function
	 */
	public Function getThunkedFunction(boolean recursive);

	/**
	 * If this function is "Thunked", an array of Thunk Function entry points is returned
	 * @return associated thunk function entry points or null if this is not a "Thunked" function.
	 */
	public Address[] getFunctionThunkAddresses();

	/**
	 * Set the currently Thunked Function or null to convert to a normal function
	 * @param thunkedFunction the thunked function or null to convert this thunked function to a 
	 * normal function.
	 * @throws IllegalArgumentException if an attempt is made to thunk a function or another
	 * thunk which would result in a loop back to this function or if this function is an external
	 * function, or specified function is from a different program instance.
	 */
	public void setThunkedFunction(Function thunkedFunction) throws IllegalArgumentException;

	/**
	 * @return true if this function is external (i.e., entry point is in EXTERNAL address space)
	 */
	@Override
	public boolean isExternal();

	/**
	 * @return if this is an external function return the associated external location object.
	 */
	public ExternalLocation getExternalLocation();

	/**
	 * Returns a set of functions that call this function.
	 * 
	 * @param monitor The monitor that is used to report progress and allow for canceling of 
	 *                the search.  May be null.
	 * @return a set of functions that call this function.
	 */
	public Set<Function> getCallingFunctions(TaskMonitor monitor);

	/**
	 * Returns a set of functions that this function calls.
	 * 
	 * @param monitor The monitor that is used to report progress and allow for canceling of 
	 *                the search.  May be null.
	 * @return a set of functions that this function calls.
	 */
	public Set<Function> getCalledFunctions(TaskMonitor monitor);

	/**
	 * Changes all local user-defined labels for this function to global symbols. If a
	 * global code symbol already exists with the same name at the symbols address the
	 * symbol will be removed. 
	 */
	public void promoteLocalUserLabelsToGlobal();

	/**
	 * Determine if this function object has been deleted.  NOTE: the function could be
	 * deleted at anytime due to asynchronous activity.  
	 * @return true if function has been deleted, false if not.
	 */
	public boolean isDeleted();
}
