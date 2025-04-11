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
package ghidra.app.plugin.core.stackeditor;

import java.net.URL;
import java.util.*;

import javax.help.UnsupportedOperationException;

import org.apache.commons.lang3.Range;
import org.apache.commons.lang3.StringUtils;

import ghidra.app.plugin.core.compositeeditor.CompositeViewerDataTypeManager;
import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.ProgramArchitecture;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.*;
import ghidra.util.exception.*;

/**
 * {@link StackFrameDataType} provides a {@link Structure} representation of a {@link StackFrame}
 * for use by the Stack Frame Editor.  Any other use is not supported since only those methods
 * required by the editor have been implemented.  This datatype is not intended to ever get
 * resolved directly into a datatype manager.  This implementation wraps a real {@link Structure}
 * which may be resolved for the purpose of tracking datatype dependencies within the editor's
 * dedicated datatype manager.
 * <P>
 * NOTE: The {@link BadDataType} is utilized within the wrapped structure to preserve stack
 * stack variables which have been defined with the {@link DataType#DEFAULT default datatype}
 * since the wrapped structure would otherwise be unable to preserve a variable name or comment.
 */
class StackFrameDataType implements Structure {

	/**
	 * Problematic areas:
	 * - Component replacement is trouble for compound storage
	 * - Auto-storage parameters should be protected since changes will be ignored (must use Function Editor).
	 * - Default ordinal-based parameter naming within editor does not account for other non-stack parameters
	 */

	private static String STACK_STRUCTURE_NAME = "{{STACK_FRAME}}";
	private static final String UNKNOWN_PREFIX = "unknown_";
	private static final String STACK_PREFIX = "stack_";

	// Partial VariableStorage serialization delimiters for use within comment string
	private static final String SERIALIZATION_START = "_{{";
	private static final String SERIALIZATION_END = "}}_";

	private final DataTypeManager dtm;
	private Structure wrappedStruct;

	private int returnAddressOffset;
	private boolean growsNegative;
	private Function function;

	private int negativeLength;
	private int positiveLength;
	private int parameterOffset; // previously named BiDirectionalDataType.splitOffset

	/**
	 * Constructor for an editable stack frame for use with the editor.
	 * The specified stack will be copied into this new instance.
	 * 
	 * @param function the function whose stack frame will be edited
	 */
	StackFrameDataType(Function function) {
		this.dtm = function.getProgram().getDataTypeManager();

		// Initialize wrapped structure from stack frame variables
		initializeFromStackFrame(function.getStackFrame());
	}

	/**
	 * Constructor for an editable stack frame for use with the editor.
	 * The specified {@link StackFrameDataType} instance will be copied into this new instance
	 * 
	 * @param stackDt stack frame editor datatype
	 * @param dtm dtm datatype manager (required)
	 */
	private StackFrameDataType(StackFrameDataType stackDt, DataTypeManager dtm) {
		this.dtm = dtm;

		// NOTE: It is assumed that the program architecture will not change!
		// Replicate state from specified stackDt instance 

		this.returnAddressOffset = stackDt.returnAddressOffset;
		this.growsNegative = stackDt.growsNegative;
		this.function = stackDt.function;
		this.negativeLength = stackDt.negativeLength;
		this.positiveLength = stackDt.positiveLength;
		this.parameterOffset = stackDt.parameterOffset;

		this.wrappedStruct = new StructureDataType(STACK_STRUCTURE_NAME, stackDt.getLength(), dtm);
		for (StackComponentWrapper wrappedDtc : stackDt.getDefinedComponents()) {
			// Replicate stored structure component details
			DataTypeComponent dtc = wrappedDtc.dtc;
			wrappedStruct.replaceAtOffset(dtc.getOffset(), dtc.getDataType(), dtc.getLength(),
				dtc.getFieldName(), dtc.getComment());
		}
	}

	private void initializeFromStackFrame(StackFrame stack) {

		returnAddressOffset = stack.getReturnAddressOffset();
		growsNegative = stack.growsNegative();
		function = stack.getFunction();
		parameterOffset = stack.getParameterOffset();

		int paramSize = stack.getParameterSize();
		int localSize = stack.getLocalSize();
		if (growsNegative) {
			// locals come first
			negativeLength = localSize;
			positiveLength = paramSize;
		}
		else {
			// params come first
			negativeLength = paramSize;
			positiveLength = localSize;
		}

		wrappedStruct = new StructureDataType(STACK_STRUCTURE_NAME, stack.getFrameSize(), dtm);

		Variable[] stackVars = stack.getStackVariables();
		for (int i = stackVars.length - 1; i >= 0; i--) {
			Variable var = stackVars[i];
			VariableStorage storage = var.getVariableStorage();
			Varnode stackVarnode = storage.getLastVarnode();
			int length = stackVarnode.getSize();
			int offset = (int) stackVarnode.getOffset();

			// TODO: Investigate is joined-stack variables are reflected in Function stack related methods
			// TODO: Why are the following checks needed?
			if (offset < (parameterOffset - negativeLength)) {
				continue;
			}
			if ((offset + length - 1) > (positiveLength + parameterOffset)) {
				continue;
			}

			String comment = buildComment(var);

			DataType dt = var.getDataType();
			if (dt == DataType.DEFAULT) {
				// Use BadDataType as placeholder within Structure
				length = 1;
				dt = BadDataType.dataType;
			}

			doReplaceAtOffset(offset, dt, length, var.getName(), comment);
		}
	}

	private static String buildComment(Variable var) {
		String nonStackStoragePart = getNonStackPartialSerializedStorage(var);
		String comment = var.getComment();
		if (nonStackStoragePart != null) {
			comment = StringUtils.join(nonStackStoragePart, comment);
		}
		return comment;
	}

	private static String getNonStackPartialSerializedStorage(Variable var) {
		VariableStorage storage = var.getVariableStorage();
		if (storage.getVarnodeCount() < 2) {
			return null;
		}
		Varnode[] varnodes = storage.getVarnodes();
		Varnode[] partialVarnodes = new Varnode[varnodes.length - 1];
		System.arraycopy(varnodes, 0, partialVarnodes, 0, partialVarnodes.length);
		String serializationString = VariableStorage.getSerializationString(partialVarnodes);
		return SERIALIZATION_START + serializationString + SERIALIZATION_END;
	}

	/**
	 * {@return newly generated stack variables based on the current state}
	 */
	Variable[] getStackVariables() {
		StackComponentWrapper[] definedComponents = getDefinedComponents();
		Variable[] vars = new Variable[definedComponents.length];
		for (int i = 0; i < vars.length; i++) {
			StackComponentWrapper dtc = definedComponents[i];
			String fieldName = dtc.getFieldName();
			VariableStorage storage = dtc.getVariableStorage();
			try {
				vars[i] = new LocalVariableImpl(fieldName, 0, dtc.getDataType(), storage,
					function.getProgram());
			}
			catch (InvalidInputException e) {
				try {
					vars[i] =
						new LocalVariableImpl(fieldName, 0, null, storage, function.getProgram());
				}
				catch (InvalidInputException e1) {
					throw new AssertException(); // Unexpected
				}
			}
			vars[i].setComment(dtc.getComment());
		}
		return vars;
	}

	/**
	 * Resolve the wrapped structure using the stack editor's datatype manager.  This is
	 * done to facilitate datatype dependency tracking immediately following instantiation of
	 * this stack frame datatype which itself cannot be resolved.
	 * <P>
	 * NOTE: It is required that this stack frame datatype instance be instantiated or copied
	 * using the original function's datyatype manager and that the editor's datatype manager
	 * has the same data organization.
	 *  
	 * @param viewDTM stack editor's datatype manager
	 */
	void resolveWrappedComposite(CompositeViewerDataTypeManager<StackFrameDataType> viewDTM) {
		wrappedStruct = (Structure) viewDTM.resolve(wrappedStruct, null);
	}

	/**
	 * {@return the original function which this stack frame corresponds to.}
	 */
	Function getFunction() {
		return function;
	}

	public boolean growsNegative() {
		return growsNegative;
	}

	public int getParameterOffset() {
		return parameterOffset;
	}

	public int getNegativeLength() {
		return negativeLength;
	}

	public int getPositiveLength() {
		return positiveLength;
	}

	public int getFrameSize() {
		return wrappedStruct.getLength();
	}

	public int getLocalSize() {
		return growsNegative ? negativeLength : positiveLength;
	}

	public int getParameterSize() {
		return growsNegative ? positiveLength : negativeLength;
	}

	public boolean setLocalSize(int size) {
		return adjustStackFrameSize(size, getLocalSize(), growsNegative);
	}

	public boolean setParameterSize(int newParamSize) {
		return adjustStackFrameSize(newParamSize, getParameterSize(), !growsNegative);
	}

	public int getReturnAddressOffset() {
		return returnAddressOffset;
	}

	private boolean adjustStackFrameSize(int newSize, int oldSize, boolean isNegative) {
		if (newSize < 0) {
			return false;
		}

		int delta = newSize - oldSize;
		if (delta == 0) {
			return true;
		}
		boolean shrinking = delta < 0;
		if (!shrinking) {
			growStructure(isNegative ? -delta : delta);
			return true;
		}

		// Handle shrinking
		int oldOffset, newOffset;
		if (isNegative) {
			oldOffset = getMinOffset();
			newOffset = oldOffset - delta;
			deleteRange(oldOffset, newOffset - 1);
		}
		else {
			oldOffset = getMaxOffset();
			newOffset = oldOffset + delta;
			deleteRange(newOffset + 1, oldOffset);
		}
		return true;
	}

	/**
	 * Deletes the indicated range of bytes from this stack frame data type.
	 * 
	 * @param minOffset the range's minimum offset on the stack frame
	 * @param maxOffset the range's maximum offset on the stack frame
	 */
	private void deleteRange(int minOffset, int maxOffset) throws IndexOutOfBoundsException {

		StackComponentWrapper dtc = getComponentContaining(minOffset);
		if (dtc == null) {
			return; // nothing to clear
		}

		int space = maxOffset - minOffset + 1;
		while (dtc != null && space > 0) {
			int ordinal = dtc.getOrdinal();
			int len = dtc.getLength();
			if (len <= space) {
				space -= len;
				delete(ordinal);
				int minOffsetLimit = parameterOffset - negativeLength;
				if (minOffset < minOffsetLimit) {
					minOffset = minOffsetLimit;
				}
			}
			else {
				// Must clear component to breakdown into undefined bytes
				clearComponent(ordinal);
			}
			dtc = getComponentContaining(minOffset);
		}
	}

	int getMinOffset() {
		return parameterOffset - negativeLength;
	}

	int getMaxOffset() {
		return parameterOffset + positiveLength - 1;
	}

	/**
	 * Effectively moves a component for a defined stack variable if it will fit where it is being
	 * moved to in the stack frame.
	 * 
	 * @param ordinal the ordinal of the component to move by changing its offset.
	 * @param newOffset the offset to move the variable to.
	 * @return the component representing the stack variable at the new offset.
	 * @throws InvalidInputException if it can't be moved.
	 * @throws IndexOutOfBoundsException if the ordinal is out of bounds
	 */
	public StackComponentWrapper setOffset(int ordinal, int newOffset)
			throws InvalidInputException, IndexOutOfBoundsException {
		final StackComponentWrapper comp = getComponent(ordinal);
		final int oldOffset = comp.getOffset();
		final int compLength = comp.getLength();
		if (newOffset == oldOffset) {
			return comp;
		}

		if ((oldOffset >= parameterOffset) && (newOffset < parameterOffset) ||
			(oldOffset < parameterOffset) && ((newOffset + compLength - 1) >= parameterOffset)) {
			throw new InvalidInputException(
				"Cannot move a stack variable/parameter across the parameter offset.");
		}

		if ((oldOffset >= 0) && (newOffset < 0) ||
			(oldOffset < 0) && ((newOffset + compLength - 1) >= 0)) {
			throw new InvalidInputException(
				"Cannot move a stack variable/parameter across the 0-offset point.");
		}

		StackComponentWrapper existing = getComponentContaining(newOffset);
		if (existing == null) {
			throw new InvalidInputException(
				getHexString(newOffset, true) + " is not an offset in this stack frame.");
		}

		if (!existing.isUndefined() && existing.getOffset() != comp.getOffset()) {
			throw new InvalidInputException("There is already another stack variable at offset " +
				getHexString(newOffset, true) + ".");
		}

		final DataType dt = comp.getDataType();
		final String fieldName = comp.getFieldName();
		final String comment = comp.getComment();

		clearComponent(ordinal);

		int mrl = getMaxLength(newOffset);
		if ((mrl != -1) && (compLength > mrl)) {
			doReplaceAtOffset(oldOffset, dt, compLength, fieldName, comment); // restore component
			throw new InvalidInputException(
				dt.getDisplayName() + " doesn't fit at offset " + getHexString(newOffset, true) +
					". It needs " + compLength + " bytes, but " + mrl + " bytes are available.");
		}

		StackComponentWrapper newComp =
			doReplaceAtOffset(newOffset, dt, compLength, fieldName, comment);
		return newComp;
	}

	/**
	 * Sets the name of the component at the specified ordinal.
	 * 
	 * @param ordinal the ordinal
	 * @param name the new name. Null indicates the default name.
	 * @return true if name change was successful, else false
	 * @throws IndexOutOfBoundsException if specified ordinal is out of range
	 * @throws IllegalArgumentException if name is invalid
	 */
	public boolean setName(int ordinal, String name) throws IndexOutOfBoundsException {

		StackComponentWrapper comp = getComponent(ordinal);
		String fieldName = comp.getFieldName();

		if (name != null) {
			name = name.trim();
			if (name.length() == 0 || isDefaultName(name)) {
				name = null;
			}
		}

		if (SystemUtilities.isEqual(name, fieldName)) {
			return false;
		}

		if (!canDefineComponent(comp.getDataType(), comp.getLength(), name, comp.getComment())) {
			// NOTE: It is unclear if we should clear component here if it previously existed
			clearComponent(ordinal);
		}
		else if (comp.isUndefined()) {
			comp = replace(comp.getOrdinal(), DataType.DEFAULT, 1, name, null);
		}
		else {
			try {
				comp.dtc.setFieldName(name);
			}
			catch (DuplicateNameException e) {
				// FIXME: Inconsistent API / how should names be validated and on which methods?
				return false;
			}
		}
		return true;
	}

	/**
	 * Sets the comment at the specified ordinal.
	 * 
	 * @param ordinal the ordinal
	 * @param comment the new comment.
	 * @return true if comment change was successful, else false
	 * @throws IndexOutOfBoundsException if specified ordinal is out of range
	 */
	public boolean setComment(int ordinal, String comment) throws IndexOutOfBoundsException {

		StackComponentWrapper comp = getComponent(ordinal);
		String oldComment = comp.getComment();

		if (comment != null) {
			comment = comment.trim();
			if (comment.length() == 0) {
				comment = null;
			}
		}
		if (comment == null) {
			if (oldComment == null) {
				return false;
			}
		}
		else if (comment.equals(oldComment)) {
			return false;
		}

		if (!canDefineComponent(comp.getDataType(), comp.getLength(), comp.getFieldName(),
			comment)) {
			// NOTE: It is unclear if we should clear component here if it previously existed
			clearComponent(ordinal);
		}
		else if (comp.isUndefined()) {
			replace(comp.getOrdinal(), DataType.DEFAULT, 1, null, comment);
		}
		else {
			// Set comment while preserving possible partial storage serialization
			String partialSerializedStorage = comp.getPartialStorageSerialization(true);
			comment = StringUtils.join(partialSerializedStorage, comment);
			comp.dtc.setComment(comment);
		}
		return true;
	}

	private boolean canDefineComponent(DataType dt, int length, String newName, String comment) {
		if (comment != null) {
			comment = comment.trim();
			if (comment.length() == 0) {
				comment = null;
			}
		}
		if (dt.isEquivalent(DataType.DEFAULT) && (newName == null || newName.length() == 0) &&
			(comment == null)) {
			return false;
		}
		return true;
	}

	/**
	 * Sets a stack component/variable data type
	 * 
	 * @param ordinal the ordinal
	 * @param dataType the data type
	 * @param length the length or size of this variable.
	 * @return the component representing this stack variable.
	 * @throws IndexOutOfBoundsException if specified ordinal is out of range
	 */
	public StackComponentWrapper setDataType(int ordinal, DataType dataType, int length)
			throws IndexOutOfBoundsException {
		StackComponentWrapper stackDtc = getComponent(ordinal);
		return replace(ordinal, dataType, length, stackDtc.getFieldName(), stackDtc.getComment());
	}

	/**
	 * Get the maximum variable size that will fit at the indicated offset if a replace is done.
	 * 
	 * @param stackOffset stack offset
	 * @return the maximum size
	 */
	public int getMaxLength(int stackOffset) {

		int structOffset = computeStructOffsetFromStackOffset(stackOffset, true);

		DataTypeComponent dtc = wrappedStruct.getComponentContaining(structOffset);
		int nextDefinedOffset = wrappedStruct.getLength();
		if (dtc != null) {
			dtc = wrappedStruct.getDefinedComponentAtOrAfterOffset(dtc.getEndOffset() + 1);
			if (dtc != null) {
				nextDefinedOffset = dtc.getOffset();
			}
		}

		int nextStackOffset = computeStackOffsetFromStructOffset(nextDefinedOffset);

		if (stackOffset < 0 && nextStackOffset > 0) {
			// Don't allow the new data type to cross from negative into positive stack space.
			nextStackOffset = 0;
		}
		if ((stackOffset < parameterOffset) && (nextStackOffset >= parameterOffset)) {
			// Don't allow the new data type to cross from local into parameter stack space.
			nextStackOffset = parameterOffset;
		}
		return nextStackOffset - stackOffset;
	}

	/**
	 * Determine if the specified variable name matches the default naming pattern.
	 * @param varName variable name.
	 * @return true if name matches default naming pattern, else false
	 */
	boolean isDefaultName(String varName) {
		if (varName == null) {
			return false;
		}
		if (varName.startsWith(STACK_PREFIX)) {
			// Detect use of stack_ prefix for default names
			varName = varName.substring(STACK_PREFIX.length());
		}
		return SymbolUtilities.isDefaultLocalStackName(varName) ||
			SymbolUtilities.isDefaultParameterName(varName);
	}

	/**
	 * Returns the default name for the indicated stack offset.
	 * 
	 * @param stackComponent stack element
	 * @return the default stack variable name.
	 */
	public String getDefaultName(StackComponentWrapper stackComponent) {
		int offset = stackComponent.getOffset();
		int paramBaseOffset = getParameterOffset();
		boolean isLocal = growsNegative ? (offset < paramBaseOffset) : (offset >= paramBaseOffset);
		if (isLocal) {
			return SymbolUtilities.getDefaultLocalName(function.getProgram(), offset, 0);
		}
		// NOTE: We really cannot produce good ordinal-based default param names since this does not
		// account for non-stack parameteres
		int index = getParameterIndex(stackComponent);
		if (index >= 0) {
			return STACK_PREFIX + SymbolUtilities.getDefaultParamName(index);
		}
		return UNKNOWN_PREFIX + Integer.toHexString(Math.abs(offset));
	}

	/**
	 * @param stackElement stack element
	 * @return the index number for this parameter (starting at 1 for the first parameter.) 0 if the
	 *         element is not a parameter.
	 */
	private int getParameterIndex(StackComponentWrapper stackElement) {
		int structOffset = stackElement.getOffset();
		StackComponentWrapper[] definedComponents = getDefinedComponents();
		int numComps = definedComponents.length;
		int firstIndex = -1; // first parameter index
		if (growsNegative) {
			for (int i = 0; i < numComps; i++) {
				DataTypeComponent dtc = definedComponents[i];
				int currentOffset = dtc.getOffset();
				if (currentOffset < parameterOffset) {
					continue;
				}
				if (firstIndex < 0) {
					firstIndex = i;
				}
				if (currentOffset == structOffset) {
					return i - firstIndex;
				}
			}
		}
		else {
			for (int i = numComps - 1; i >= 0; i--) {
				DataTypeComponent dtc = definedComponents[i];
				int currentOffset = dtc.getOffset();
				if (currentOffset >= parameterOffset) {
					continue;
				}
				if (firstIndex < 0) {
					firstIndex = i;
				}
				if (currentOffset == structOffset) {
					return firstIndex - i;
				}
			}
		}
		return 0;
	}

	/**
	 * Returns true if a stack variable is defined at the specified ordinal.
	 * 
	 * @param ordinal stack frame ordinal
	 * @return true if variable is defined at ordinal or false if undefined.
	 */
	public boolean isStackVariable(int ordinal) {
		DataTypeComponent stackElement = getDefinedComponentAtOrdinal(ordinal);
		return stackElement != null;
	}

	/**
	 * {@return true if the specified stackOffset corresponds to a function parameter}
	 * @param stackOffset stack frame offset
	 */
	boolean isParameterOffset(int stackOffset) {
		int paramStart = getParameterOffset();
		return (growsNegative && stackOffset >= paramStart) ||
			(!growsNegative && stackOffset < paramStart);
	}

	/**
	 * Determine if the specified stackOffset corresponds to a parameter which should not be 
	 * modified via the stack editor other than its name and comment.  This is neccessary when
	 * (i.e., custom storage is disabled) in which case the function signature should be adjusted
	 * using the Function Editor.
	 * 
	 * @param stackOffset stack frame offset
	 * @return true if the specified stackOffset corresponds to a protected parameter with 
	 * an auto storage assignment.
	 */
	boolean isProtectedParameterOffset(int stackOffset) {
		return isParameterOffset(stackOffset) && !function.hasCustomVariableStorage();
	}

	/**
	 * Get a formatted signed-hex value
	 * @param offset the value to be formatted
	 * @param showPrefix if true the "0x" hex prefix will be included
	 * @return formatted signed-hex value
	 */
	public static String getHexString(int offset, boolean showPrefix) {
		String prefix = showPrefix ? "0x" : "";
		return ((offset >= 0) ? (prefix + Integer.toHexString(offset))
				: ("-" + prefix + Integer.toHexString(-offset)));
	}

	private int computeStructOffsetFromStackOffset(int stackOffset, boolean doCheckDefinedOffset) {
		int structOffset = stackOffset + negativeLength - parameterOffset; // parameterOffset - negativeLength + stackOffset;
		if (doCheckDefinedOffset &&
			(structOffset < 0 || structOffset >= wrappedStruct.getLength())) {
			throw new IllegalArgumentException("Offset " + getHexString(stackOffset, true) +
				" is not a defined within the stack frame");
		}
		return structOffset;
	}

	private int computeStackOffsetFromStructOffset(int structOffset) {
		return structOffset - negativeLength + parameterOffset; //  structOffset + negativeLength - parameterOffset;
	}

	/**
	 * If a stack variable is defined in the editor at the specified offset, this retrieves the
	 * editor element containing that stack variable <BR>
	 * Note: if a stack variable isn't defined at the indicated offset then null is returned.
	 * 
	 * @param stackOffset the stack offset
	 * @return the stack editor's element at the stackOffset. Otherwise, null.
	 */
	public StackComponentWrapper getDefinedComponentAtOffset(int stackOffset) {
		StackComponentWrapper stackDtc = getDefinedComponentAtOrAfterOffset(stackOffset);
		if (stackDtc != null && stackDtc.getOffset() == stackOffset) {
			return stackDtc;
		}
		return null;
	}

	/**
	 * If a stack variable is defined in the editor at the specified ordinal, this retrieves the
	 * editor element containing that stack variable. <BR>
	 * 
	 * @param ordinal the ordinal
	 * @return the stack editor's element at the ordinal or null if an undefined location within
	 * the bounds of the stack.
	 * @throws IndexOutOfBoundsException if the ordinal is out of bounds
	 */
	public StackComponentWrapper getDefinedComponentAtOrdinal(int ordinal)
			throws IndexOutOfBoundsException {
		DataTypeComponent dtc = wrappedStruct.getComponent(ordinal);
		return (dtc != null && !dtc.isUndefined()) ? new StackComponentWrapper(dtc) : null;
	}

	private void validateStackComponentDataType(DataType dataType) {
		if (DataTypeComponent.usesZeroLengthComponent(dataType)) {
			throw new IllegalArgumentException(
				"Zero-length datatype not permitted: " + dataType.getName());
		}
		if (dataType instanceof BitFieldDataType) {
			throw new IllegalArgumentException("Bitfield not permitted: " + dataType.getName());
		}
	}

	/**
	 * {@link StackComponentWrapper} wraps and standard {@link Structure}
	 * {@link DataTypeComponent} and provides the neccessary stack offset 
	 * translation.
	 */
	class StackComponentWrapper implements DataTypeComponent {

		final DataTypeComponent dtc;

		StackComponentWrapper(DataTypeComponent dtc) {
			this.dtc = dtc;
			if (dtc instanceof StackComponentWrapper) {
				// Must not wrap the wrapper
				throw new IllegalArgumentException();
			}
		}

		@Override
		public DataType getDataType() {
			DataType dt = dtc.getDataType();
			if (dt instanceof BadDataType && getLength() == 1) {
				return DataType.DEFAULT;
			}
			return dt;
		}

		@Override
		public DataType getParent() {
			return StackFrameDataType.this;
		}

		@Override
		public boolean isBitFieldComponent() {
			return false;
		}

		@Override
		public boolean isZeroBitFieldComponent() {
			return false;
		}

		@Override
		public int getOrdinal() {
			return dtc.getOrdinal();
		}

		/**
		 * {@return true if this component corresponds to a function parameter}
		 */
		boolean isParameter() {
			int paramStart = getParameterOffset();
			int stackOffset = getOffset();
			return (growsNegative && stackOffset >= paramStart) ||
				(!growsNegative && stackOffset < paramStart);
		}

		/**
		 * Determine if this component corresponds to a parameter which should not be 
		 * modified via the stack editor other than its name and comment.  This is neccessary when
		 * (i.e., custom storage is disabled) in which case the function signature should be adjusted
		 * using the Function Editor.
		 * 
		 * @return true if this component corresponds to a protected parameter with 
		 * an auto storage assignment.
		 */
		boolean isProtectedParameter() {
			return isParameter() && !function.hasCustomVariableStorage();
		}

		@Override
		public int getOffset() {
			return computeStackOffsetFromStructOffset(dtc.getOffset());
		}

		@Override
		public int getEndOffset() {
			return computeStackOffsetFromStructOffset(dtc.getEndOffset());
		}

		@Override
		public int getLength() {
			return dtc.getLength();
		}

		/**
		 * Unsupported method.  Must use {@link StackFrameDataType#setComment(int, String)}.
		 */
		@Override
		public void setComment(String comment) {
			throw new UnsupportedOperationException();
		}

		@Override
		public String getComment() {
			String comment = dtc.getComment();
			if (comment != null && comment.startsWith(SERIALIZATION_START)) {
				int ix = comment.indexOf(SERIALIZATION_END);
				if (ix > 0) {
					comment = comment.substring(ix + SERIALIZATION_END.length());
				}
			}
			return StringUtils.isBlank(comment) ? null : comment;
		}

		private String getPartialStorageSerialization(boolean stripStartEnd) {
			String comment = dtc.getComment();
			if (comment != null && comment.startsWith(SERIALIZATION_START)) {
				int ix = comment.indexOf(SERIALIZATION_END);
				if (ix > 0) {
					int startIx = stripStartEnd ? SERIALIZATION_START.length() : 0;
					int endIx = ix + (stripStartEnd ? 0 : SERIALIZATION_END.length());
					return comment.substring(startIx, endIx);
				}
			}
			return null;
		}

		private VariableStorage getVariableStorage() {
			ProgramArchitecture programArchitecture = dtm.getProgramArchitecture();

			// Extract partial non-stack storage serialization from comment
			Varnode[] partialStorage = null;
			String partialSerializedStorage = getPartialStorageSerialization(true);
			if (partialSerializedStorage != null) {
				try {
					partialStorage =
						VariableStorage.deserialize(programArchitecture, partialSerializedStorage)
								.getVarnodes();
				}
				catch (InvalidInputException e) {
					// ignore
				}
			}

			try {
				Address stackAddr =
					programArchitecture.getAddressFactory().getStackSpace().getAddress(getOffset());
				Varnode stackVarnode = new Varnode(stackAddr, getLength());

				if (partialStorage != null) {
					Varnode[] joinedVarnodes = new Varnode[partialStorage.length + 1];
					System.arraycopy(partialStorage, 0, joinedVarnodes, 0, partialStorage.length);
					joinedVarnodes[partialStorage.length] = stackVarnode;
					return new VariableStorage(programArchitecture, joinedVarnodes);
				}

				return new VariableStorage(programArchitecture, stackVarnode);
			}
			catch (InvalidInputException e) {
				Msg.error(this, "Failed to build variable: " + e.getMessage());
				try {
					// fallback on error to single byte stack varnode
					return new VariableStorage(programArchitecture, getOffset(), 1);
				}
				catch (InvalidInputException e1) {
					throw new AssertException(e1); // unexpected
				}
			}
		}

		@Override
		public Settings getDefaultSettings() {
			return dtc.getDefaultSettings();
		}

		@Override
		public String getFieldName() {
			return dtc.getFieldName();
		}

		/**
		 * Unsupported method.  Must use {@link StackFrameDataType#setName(int, String)}.
		 */
		@Override
		public void setFieldName(String fieldName) throws DuplicateNameException {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean isEquivalent(DataTypeComponent otherDtc) {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean isUndefined() {
			return dtc.isUndefined();
		}

		@Override
		public String toString() {
			return InternalDataTypeComponent.toString(this);
		}
	}

	//
	// Supported Structure methods.  Some methods may need to handle stack offset transformation
	//

	@Override
	public StackFrameDataType clone(DataTypeManager dataMgr) {
		if (dtm == dataMgr) {
			return this;
		}
		return copy(dataMgr);
	}

	@Override
	public StackFrameDataType copy(DataTypeManager dataMgr) {
		return new StackFrameDataType(this, dataMgr);
	}

	@Override
	public DataTypeManager getDataTypeManager() {
		return dtm;
	}

	@Override
	public DataOrganization getDataOrganization() {
		return wrappedStruct.getDataOrganization();
	}

	@Override
	public int getLength() {
		return wrappedStruct.getLength();
	}

	@Override
	public String getName() {
		return function.getName();
	}

	@Override
	public String getPathName() {
		return getName();
	}

	@Override
	public String getDisplayName() {
		return getName();
	}

	@Override
	public boolean isEquivalent(DataType dt) {
		if (!(dt instanceof StackFrameDataType stackDt) || function != stackDt.function) {
			throw new IllegalStateException("Expected the same function for supported use");
		}
		return wrappedStruct.isEquivalent(stackDt.wrappedStruct);
	}

	@Override
	public String getDescription() {
		return "Stack Frame: " + getName();
	}

	@Override
	public int getAlignedLength() {
		return getLength();
	}

	@Override
	public boolean isZeroLength() {
		return false;
	}

	@Override
	public boolean isNotYetDefined() {
		return false;
	}

	@Override
	public PackingType getPackingType() {
		return PackingType.DISABLED;
	}

	@Override
	public int getNumComponents() {
		return wrappedStruct.getNumComponents();
	}

	@Override
	public int getNumDefinedComponents() {
		return wrappedStruct.getNumDefinedComponents();
	}

	@Override
	public CategoryPath getCategoryPath() {
		return CategoryPath.ROOT;
	}

	@Override
	public DataTypePath getDataTypePath() {
		return new DataTypePath(CategoryPath.ROOT, getName());
	}

	@Override
	public StackComponentWrapper[] getDefinedComponents() {
		DataTypeComponent[] components = wrappedStruct.getDefinedComponents();
		StackComponentWrapper[] wrappedComponents = new StackComponentWrapper[components.length];
		for (int i = 0; i < components.length; i++) {
			wrappedComponents[i] = new StackComponentWrapper(components[i]);
		}
		return wrappedComponents;
	}

	@Override
	public StackComponentWrapper getDefinedComponentAtOrAfterOffset(int stackOffset) {
		int structOffset = computeStructOffsetFromStackOffset(stackOffset, false);
		DataTypeComponent dtc = wrappedStruct.getDefinedComponentAtOrAfterOffset(structOffset);
		return dtc != null ? new StackComponentWrapper(dtc) : null;
	}

	@Override
	public StackComponentWrapper getComponentContaining(int stackOffset) {
		int structOffset = computeStructOffsetFromStackOffset(stackOffset, false);
		DataTypeComponent dtc = wrappedStruct.getComponentContaining(structOffset);
		return dtc != null ? new StackComponentWrapper(dtc) : null;
	}

	@Override
	public StackComponentWrapper getComponent(int ordinal) throws IndexOutOfBoundsException {
		DataTypeComponent dtc = wrappedStruct.getComponent(ordinal);
		return new StackComponentWrapper(dtc);
	}

	@Override
	public void clearComponent(int ordinal) throws IndexOutOfBoundsException {
		wrappedStruct.clearComponent(ordinal);
	}

	@Override
	public void clearAtOffset(int stackOffset) {
		int structOffset = computeStructOffsetFromStackOffset(stackOffset, true);
		wrappedStruct.clearAtOffset(structOffset);
	}

	@Override
	public void delete(int ordinal) throws IndexOutOfBoundsException {
		StackComponentWrapper dtc = getComponent(ordinal);
		if (dtc == null) {
			return;
		}
		int stackOffset = dtc.getOffset();
		int len = dtc.getLength();

		wrappedStruct.delete(ordinal);

		Range<Integer> r = Range.between(stackOffset, stackOffset + len - 1);
		if (r.contains(parameterOffset)) {
			int negLenReduction = parameterOffset - stackOffset;
			negativeLength -= negLenReduction;
			positiveLength -= len - negLenReduction;
		}
		else if (r.isBefore(parameterOffset)) {
			negativeLength -= len;
		}
		else {
			positiveLength -= len;
		}
	}

	@Override
	public StackComponentWrapper[] getComponents() {
		DataTypeComponent[] components = wrappedStruct.getComponents();
		StackComponentWrapper[] wrappedComponents = new StackComponentWrapper[components.length];
		for (int i = 0; i < components.length; i++) {
			wrappedComponents[i] = new StackComponentWrapper(components[i]);
		}
		return wrappedComponents;
	}

	@Override
	public StackComponentWrapper getComponentAt(int stackOffset) {
		int structOffset = computeStructOffsetFromStackOffset(stackOffset, false);
		DataTypeComponent dtc = wrappedStruct.getComponentAt(structOffset);
		return dtc != null ? new StackComponentWrapper(dtc) : null;
	}

	@Override
	public void growStructure(int amount) {

		if (amount < 0) {
			negativeLength -= amount;

			// Push all defined components down based on negative size increase.
			// Since we cannot directly manipulate offsets we must insert a defined component
			// then clear it.
			wrappedStruct.insert(0, Undefined.getUndefinedDataType(-amount));
			wrappedStruct.clearComponent(0);
		}
		else {
			positiveLength += amount;
			wrappedStruct.growStructure(amount);
		}
	}

	/**
	 * Check for possible stack growth and adjust positiveLength as needed.
	 * This method shuold be invoked if changes are made to the wrapped structure by the
	 * datatype manager in response to datatype dependency changes they may trigger positive 
	 * growth.
	 */
	void checkForStackGrowth() {
		int delta = wrappedStruct.getLength() - positiveLength - negativeLength;
		if (delta > 0) {
			positiveLength += delta;
		}
	}

	private StackComponentWrapper doReplaceAtOffset(int stackOffset, DataType dataType, int length,
			String name, String comment) throws IllegalArgumentException {

		int structOffset = computeStructOffsetFromStackOffset(stackOffset, true);

		validateStackComponentDataType(dataType);

		if (dataType == DataType.DEFAULT) {
			dataType = BadDataType.dataType;
			length = 1;
		}

		if (name != null && isDefaultName(name)) {
			name = null;
		}

		DataTypeComponent dtc =
			wrappedStruct.replaceAtOffset(structOffset, dataType, length, name, comment);

		checkForStackGrowth();

		return new StackComponentWrapper(dtc);
	}

	@Override
	public StackComponentWrapper replace(int ordinal, DataType dataType, int length, String name,
			String comment) throws IndexOutOfBoundsException, IllegalArgumentException {

		validateStackComponentDataType(dataType);

		if (dataType == DataType.DEFAULT) {
			dataType = BadDataType.dataType;
			length = 1;
		}

		if (name != null && isDefaultName(name)) {
			name = null;
		}

		DataTypeComponent dtc = wrappedStruct.replace(ordinal, dataType, length, name, comment);

		checkForStackGrowth();

		return new StackComponentWrapper(dtc);
	}

	//
	// Unused/Unsupported Structure methods
	// Implementation is tailored specifically for use for Stack Editor
	//

	@Override
	public void setName(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setLength(int length) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setDescription(String desc) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataTypeComponent add(DataType dataType) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataTypeComponent add(DataType dataType, int length) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataTypeComponent add(DataType dataType, String name, String comment) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataTypeComponent add(DataType dataType, int length, String name, String comment) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataTypeComponent addBitField(DataType baseDataType, int bitSize, String componentName,
			String comment) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataTypeComponent insert(int ordinal, DataType dataType) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataTypeComponent insert(int ordinal, DataType dataType, int length) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataTypeComponent insert(int ordinal, DataType dataType, int length, String name,
			String comment) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void deleteAtOffset(int stackOffset) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void delete(Set<Integer> ordinals) throws IndexOutOfBoundsException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void deleteAll() {
		throw new UnsupportedOperationException();
	}

	@Override
	public StackComponentWrapper replaceAtOffset(int stackOffset, DataType dataType, int length,
			String newName, String comment) throws IllegalArgumentException {
		throw new UnsupportedOperationException();
	}

	@Override
	public StackComponentWrapper replace(int ordinal, DataType dataType, int length)
			throws IndexOutOfBoundsException, IllegalArgumentException {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataTypeComponent insertAtOffset(int offset, DataType dataType, int length) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataTypeComponentImpl insertAtOffset(int offset, DataType dataType, int length,
			String newName, String comment) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataTypeComponent insertBitField(int ordinal, int byteWidth, int bitOffset,
			DataType baseDataType, int bitSize, String componentName, String comment) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataTypeComponent insertBitFieldAt(int byteOffset, int byteWidth, int bitOffset,
			DataType baseDataType, int bitSize, String componentName, String comment) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isPartOf(DataType dataType) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void dataTypeAlignmentChanged(DataType dt) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void repack() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setPackingEnabled(boolean enabled) {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getExplicitPackingValue() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setExplicitPackingValue(int packingValue) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setToDefaultPacking() {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getAlignment() {
		throw new UnsupportedOperationException();
	}

	@Override
	public AlignmentType getAlignmentType() {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getExplicitMinimumAlignment() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setExplicitMinimumAlignment(int minAlignment) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setToDefaultAligned() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setToMachineAligned() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean hasLanguageDependantLength() {
		throw new UnsupportedOperationException();
	}

	@Override
	public SettingsDefinition[] getSettingsDefinitions() {
		throw new UnsupportedOperationException();
	}

	@Override
	public TypeDefSettingsDefinition[] getTypeDefSettingsDefinitions() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Settings getDefaultSettings() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setCategoryPath(CategoryPath path) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setNameAndCategory(CategoryPath path, String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getMnemonic(Settings settings) {
		throw new UnsupportedOperationException();
	}

	@Override
	public URL getDocs() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isEncodable() {
		throw new UnsupportedOperationException();
	}

	@Override
	public byte[] encodeValue(Object value, MemBuffer buf, Settings settings, int length) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getDefaultLabelPrefix() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getDefaultAbbreviatedLabelPrefix() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getDefaultLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getDefaultOffcutLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options, int offcutOffset) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		throw new UnsupportedOperationException();
	}

	@Override
	public byte[] encodeRepresentation(String repr, MemBuffer buf, Settings settings, int length) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isDeleted() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void dataTypeSizeChanged(DataType dt) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void dataTypeDeleted(DataType dt) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void dataTypeReplaced(DataType oldDt, DataType newDt) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void dataTypeNameChanged(DataType dt, String oldName) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void addParent(DataType dt) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeParent(DataType dt) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Collection<DataType> getParents() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean dependsOn(DataType dt) {
		throw new UnsupportedOperationException();
	}

	@Override
	public SourceArchive getSourceArchive() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setSourceArchive(SourceArchive archive) {
		throw new UnsupportedOperationException();
	}

	@Override
	public long getLastChangeTime() {
		throw new UnsupportedOperationException();
	}

	@Override
	public long getLastChangeTimeInSourceArchive() {
		throw new UnsupportedOperationException();
	}

	@Override
	public UniversalID getUniversalID() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void replaceWith(DataType dataType) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setLastChangeTime(long lastChangeTime) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setLastChangeTimeInSourceArchive(long lastChangeTimeInSourceArchive) {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<DataTypeComponent> getComponentsContaining(int offset) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataTypeComponent getDataTypeAt(int offset) {
		throw new UnsupportedOperationException();
	}

}
