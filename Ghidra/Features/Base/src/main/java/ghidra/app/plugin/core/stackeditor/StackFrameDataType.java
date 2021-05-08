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

import java.util.Collections;
import java.util.Iterator;

import ghidra.docking.settings.Settings;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.InvalidInputException;

/**
 * StackFrameDataType provides an editable copy of a function stack frame.
 */
public class StackFrameDataType extends BiDirectionDataType {

	private static final long serialVersionUID = 1L;
	static String DUMMY_FUNCTION_NAME = "StackWithoutFunction";
	private static final String UNKNOWN_PREFIX = "unknown_";
	StackFrame stack;
	int returnAddressOffset;
	boolean growsNegative;
	Function function;

	/**
	 * Constructor for an editable stack frame for use with the editor.
	 * 
	 * @param stack the function stack frame to be edited.
	 */
	public StackFrameDataType(StackFrame stack, DataTypeManager dtm) {
		super(
			(stack.getFunction() != null) ? stack.getFunction().getName() : "StackWithoutFunction",
			0, 0, stack.getParameterOffset(), dtm);
		this.stack = stack;
		initialize();
	}

	/**
	 * Constructor for an editable stack frame for use with the editor.
	 * 
	 * @param stack the function stack frame to be edited.
	 */
	public StackFrameDataType(StackFrameDataType stackDt, DataTypeManager dtm) {
		super(stackDt.getCategoryPath(), stackDt.getName(), stackDt.getNegativeLength(),
			stackDt.getPositiveLength(), stackDt.splitOffset, dtm);
		setDescription(stackDt.getDescription());
		this.function = stackDt.function;
		this.growsNegative = stackDt.growsNegative;
		this.returnAddressOffset = stackDt.returnAddressOffset;
		this.stack = stackDt.stack;
		this.defaultSettings = stackDt.defaultSettings;
		for (DataTypeComponentImpl dtc : stackDt.components) {
			replaceAtOffset(dtc.getOffset(), dtc.getDataType(), dtc.getLength(), dtc.getFieldName(),
				dtc.getComment());
		}
	}

	StackFrame getStackFrame() {
		return stack;
	}

	private void initialize() {
		this.function = stack.getFunction();
		int paramSize = stack.getParameterSize();
		int localSize = stack.getLocalSize();
		this.returnAddressOffset = stack.getReturnAddressOffset();
		this.growsNegative = stack.growsNegative();
		int negLength;
		int posLength;
		if (growsNegative) {
			// locals come first
			negLength = -localSize;
			posLength = paramSize;
		}
		else {
			// params come first
			negLength = -paramSize;
			posLength = localSize;
		}

		growStructure(posLength);
		growStructure(negLength);

		Variable[] stackVars = stack.getStackVariables();
		for (int i = stackVars.length - 1; i >= 0; i--) {
			Variable var = stackVars[i];
			VariableStorage storage = var.getVariableStorage();
			Varnode stackVarnode = storage.getLastVarnode();
			int length = stackVarnode.getSize();
			int offset = (int) stackVarnode.getOffset();
			if (offset < (negLength + splitOffset)) {
				continue;
			}
			if ((offset + length - 1) > (posLength + splitOffset)) {
				continue;
			}
			String comment = var.getComment();
			if (comment != null) {
				comment = comment.trim();
				if (comment.length() == 0) {
					comment = null;
				}
			}
			String varName = var.getName();
			DataType dt = var.getDataType();
			if (!storage.isStackStorage()) {
				// Compound storage where only the last piece is on the stack
				// Create a datatype to represent this piece
				dt = new StackPieceDataType(var, getDataTypeManager());
			}
			replaceAtOffset(offset, dt, length, (isDefaultName(varName)) ? null : varName, comment);
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DataType#getRepresentation(ghidra.program.model.mem.MemBuffer, ghidra.util.settings.Settings, int)
	 */
	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return "";
	}

	boolean isDefaultName(String varName) {
		if (varName == null) {
			return false;
		}
		return SymbolUtilities.isDefaultLocalStackName(varName) ||
			SymbolUtilities.isDefaultParameterName(varName);
	}

	@Override
	public StackFrameDataType clone(DataTypeManager dtm) {
		return new StackFrameDataType(this, dtm);
	}

	int getMinOffset() {
		return splitOffset - negativeLength;
	}

	int getMaxOffset() {
		return splitOffset + positiveLength - 1;
	}

	public static String getHexString(int offset, boolean showPrefix) {
		String prefix = showPrefix ? "0x" : "";
		return ((offset >= 0) ? (prefix + Integer.toHexString(offset))
				: ("-" + prefix + Integer.toHexString(-offset)));
	}

	/**
	 * If a stack variable is defined in the editor at the specified offset, this retrieves the
	 * editor element containing that stack variable <BR>
	 * Note: if a stack variable isn't defined at the indicated offset then null is returned.
	 * 
	 * @param offset the offset
	 * @return the stack editor's element at the offset. Otherwise, null.
	 */
	public DataTypeComponent getDefinedComponentAtOffset(int offset) {
		if (offset < getMinOffset() || offset > getMaxOffset()) {
			throw new ArrayIndexOutOfBoundsException(offset);
		}
		int index = Collections.binarySearch(components, new Integer(offset), offsetComparator);
		if (index >= 0) {
			return components.get(index);
		}
		return null;
	}

	/**
	 * If a stack variable is defined in the editor at the specified ordinal, this retrieves the
	 * editor element containing that stack variable. <BR>
	 * Note: if a stack variable isn't defined for the indicated ordinal then null is returned.
	 * 
	 * @param ordinal the ordinal
	 * @return the stack editor's element at the ordinal. Otherwise, null.
	 */
	public DataTypeComponent getDefinedComponentAtOrdinal(int ordinal) {
		if (ordinal < 0 || ordinal >= getNumComponents()) {
			throw new ArrayIndexOutOfBoundsException(ordinal);
		}
		int index = Collections.binarySearch(components, new Integer(ordinal), ordinalComparator);
		if (index >= 0) {
			return components.get(index);
		}
		return null;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.listing.StackFrame#getFunction()
	 */
	public Function getFunction() {
		return function;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.listing.StackFrame#getFrameSize()
	 */
	public int getFrameSize() {
		return getLength();
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.listing.StackFrame#getLocalSize()
	 */
	public int getLocalSize() {
		return growsNegative ? negativeLength : positiveLength;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.listing.StackFrame#getParameterSize()
	 */
	public int getParameterSize() {

		// TODO: Does size of last positive param need to be factored in ??

//		DataTypeComponent[] variables = getDefinedComponents();
//		int lastParamSize = 0;
//		if (variables.length != 0) {
//			DataTypeComponent var = variables[variables.length-1];
//			if (var.getOffset() >= getParameterOffset()) {
//				lastParamSize = var.getLength();
//			}
//		}

		return growsNegative ? positiveLength : negativeLength;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.listing.StackFrame#getParameterOffset()
	 */
	public int getParameterOffset() {
		return splitOffset;
	}

	public boolean setLocalSize(int size) {
		return adjustStackFrameSize(size, getLocalSize(), growsNegative);
	}

	public boolean setParameterSize(int newParamSize) {
		return adjustStackFrameSize(newParamSize, getParameterSize(), !growsNegative);
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

//	private int getFirstParameterLength() {
//		Object offsetKey = new Integer(0);
//		DataTypeComponent[] variables = getDefinedComponents();
//		int loc = Arrays.binarySearch(variables, offsetKey, offsetComparator);
//		loc = (loc < 0 ? -1 - loc : loc);
//		if (!growsNegative()) {
//			loc--;
//		}
//		if (loc >= 0 && loc < variables.length) {
//			DataTypeComponent var = variables[loc];
//			if (var != null) {
//				return var.getLength();
//			}
//		}
//		return 0;
//	}

	void shiftParamOffset(int offset, int deltaOrdinal, int deltaLength) {
		int index = Collections.binarySearch(components, new Integer(offset), offsetComparator);
		if (index < 0) {
			index = -index - 1;
		}

		adjustOffsets(index, offset, deltaOrdinal, deltaLength);
		numComponents += deltaOrdinal;
		notifySizeChanged();
	}

	/**
	 * Undefines any defined stack variables in the indicated offset range.
	 * 
	 * @param minOffset the range's minimum offset on the stack frame
	 * @param maxOffset the range's maximum offset on the stack frame
	 */
	@SuppressWarnings("unused")
	private void clearRange(int minOffset, int maxOffset) {
		int first = Collections.binarySearch(components, new Integer(minOffset), offsetComparator);
		if (first < 0) {
			first = -first - 1;
		}
		int last = Collections.binarySearch(components, new Integer(maxOffset), offsetComparator);
		if (last < 0) {
			last = -last - 2;
		}
		for (int index = first; index < last; index++) {
			clearComponent(index);
		}
	}

	/**
	 * Deletes the indicated range of bytes from this stack frame data type.
	 * 
	 * @param minOffset the range's minimum offset on the stack frame
	 * @param maxOffset the range's maximum offset on the stack frame
	 */
	private void deleteRange(int minOffset, int maxOffset) {
		// FUTURE: improve the efficiency of this.
		int minOrdinal = getComponentAt(minOffset).getOrdinal();
		clearComponent(minOrdinal);
		int maxOrdinal = getComponentAt(maxOffset).getOrdinal();
		clearComponent(maxOrdinal);
		minOrdinal = getComponentAt(minOffset).getOrdinal();
		maxOrdinal = getComponentAt(maxOffset).getOrdinal();
		for (int i = maxOrdinal; i >= minOrdinal; i--) {
			delete(i);
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.listing.StackFrame#getReturnAddressOffset()
	 */
	public int getReturnAddressOffset() {
		return returnAddressOffset;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.listing.StackFrame#clearVariable(int)
	 */
	public void clearComponentAt(int offset) {
		if (offset < getMinOffset() || offset > getMaxOffset()) {
			throw new ArrayIndexOutOfBoundsException(offset);
		}
		int index = Collections.binarySearch(components, new Integer(offset), offsetComparator);
		if (index >= 0) {
			clearComponent(index);
		}
	}

	public Variable[] getStackVariables() {
		Variable[] vars = new Variable[components.size()];
		Iterator<DataTypeComponentImpl> iter = components.iterator();
		for (int i = 0; iter.hasNext(); i++) {
			DataTypeComponent dtc = iter.next();
			String fieldName = dtc.getFieldName();
			int offset = dtc.getOffset();
			try {
				vars[i] = new LocalVariableImpl(fieldName, dtc.getDataType(), offset,
					function.getProgram());
			}
			catch (InvalidInputException e) {
				try {
					vars[i] = new LocalVariableImpl(fieldName, null, offset, function.getProgram());
				}
				catch (InvalidInputException e1) {
					throw new AssertException(); // Unexpected
				}
			}
			vars[i].setComment(dtc.getComment());
		}
		return vars;
	}

	public boolean growsNegative() {
		return growsNegative;
	}

	/**
	 * Sets the name of the component at the specified ordinal.
	 * 
	 * @param ordinal the ordinal
	 * @param name the new name. Null indicates the default name.
	 */
	public boolean setName(int ordinal, String name) {
		validateName(ordinal, name);
		DataTypeComponent comp = getComponent(ordinal);
		String fieldName = comp.getFieldName();
		if ((name != null) && ((name.length() == 0) || (isDefaultName(name)))) {
			name = null;
		}
		if (name == null) {
			if (fieldName == null) {
				return false;
			}
		}
		else if (name.equals(fieldName)) {
			return false;
		}
		DataType dt = comp.getDataType();
		int length = comp.getLength();
		String comment = comp.getComment();
		if (canDefineComponent(dt, length, name, comment)) {
			DataTypeComponent newComp = replace(comp.getOrdinal(), dt, length, name, comment);
			return (newComp != null);
		}
		clearComponent(ordinal);
		return true;
	}

	/**
	 * Sets the comment at the specified ordinal.
	 * 
	 * @param ordinal the ordinal
	 * @param comment the new comment.
	 */
	public boolean setComment(int ordinal, String comment) {
		DataTypeComponent comp = getComponent(ordinal);
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
		DataType dt = comp.getDataType();
		int length = comp.getLength();
		String fieldName = comp.getFieldName();
		if (canDefineComponent(dt, length, fieldName, comment)) {
			DataTypeComponent newComp = replace(comp.getOrdinal(), dt, length, fieldName, comment);
			return (newComp != null);
		}
		clearComponent(ordinal);
		return true;
	}

	/**
	 * @return
	 */
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
	 * Currently no validation is done on the name.
	 * 
	 * @param ordinal
	 * @param newName
	 * @throws InvalidNameException
	 */
	void validateName(int ordinal, String newName)
//	throws InvalidNameException 
	{
//		if (newName == null || newName.length() == 0) {
//			return;
//		}
//		// FUTURE: check that name is unique.
//		ListIterator iter = components.listIterator();
//		while (iter.hasNext()) {
//			DataTypeComponent element = (DataTypeComponent) iter.next();
//			if (element.getOrdinal() == ordinal) {
//				continue;
//			}
//			if (newName.equals(element.getFieldName())) {
//				throw new InvalidNameException("The name \""+newName
//									+"\" is already in use at offset "
//									+getHexString(element.getOffset(), true)+".");
//			}
//		}
	}

	/**
	 * Effectively moves a component for a defined stack variable if it will fit where it is being
	 * moved to in the stack frame.
	 * 
	 * @param ordinal the ordinal of the component to move by changing its offset.
	 * @param newOffset the offset to move the variable to.
	 * @return the component representing the stack variable at the new offset.
	 * @throws InvalidInputException if it can't be moved.
	 */
	public DataTypeComponent setOffset(int ordinal, int newOffset) throws InvalidInputException {
		DataTypeComponent comp = getComponent(ordinal);
		int oldOffset = comp.getOffset();
		int compLength = comp.getLength();
		if (newOffset == oldOffset) {
			return comp;
		}
		if ((oldOffset >= splitOffset) && (newOffset < splitOffset) ||
			(oldOffset < splitOffset) && (newOffset >= splitOffset)) {
			throw new InvalidInputException(
				"Cannot move a stack variable/parameter across the parameter offset.");
		}
		clearComponent(ordinal);
		DataTypeComponent existing = getDefinedComponentAt(newOffset);
		if (existing != null) {
			replaceAtOffset(oldOffset, comp.getDataType(), comp.getLength(), comp.getFieldName(),
				comp.getComment());
			throw new InvalidInputException("There is already a stack variable at offset " +
				getHexString(newOffset, true) + ".");
		}
		existing = getComponentAt(newOffset);
		int mrl = getMaxLength(newOffset);
		if ((mrl != -1) && (compLength > mrl)) {
			replaceAtOffset(oldOffset, comp.getDataType(), comp.getLength(), comp.getFieldName(),
				comp.getComment());
			throw new InvalidInputException(comp.getDataType().getDisplayName() +
				" doesn't fit at offset " + getHexString(newOffset, true) + ". It needs " +
				compLength + " bytes, but " + mrl + " bytes are available.");
		}
		String defaultName = getDefaultName(comp);
		String oldName = comp.getFieldName();
		boolean isDefault = (oldName == null) || (oldName.equals(defaultName));
		DataTypeComponent newComp = replaceAtOffset(newOffset, comp.getDataType(), comp.getLength(),
			isDefault ? null : oldName, comp.getComment());
		return newComp;
	}

	/**
	 * Sets a component representing the defined stack variable at the indicated ordinal to have the
	 * specified data type and length.
	 * 
	 * @param ordinal the ordinal
	 * @param type the data type
	 * @param length the length or size of this variable.
	 * @return the component representing this stack variable.
	 */
	public DataTypeComponent setDataType(int ordinal, DataType type, int length) {
		DataTypeComponent dtc = getComponent(ordinal);
		return replace(ordinal, type, length, dtc.getFieldName(), dtc.getComment());
	}

	/**
	 * Get the maximum variable size that will fit at the indicated offset if a replace is done.
	 * 
	 * @param offset
	 * @return the maximum size
	 */
	public int getMaxLength(int offset) {
		if (offset < getMinOffset() || offset > getMaxOffset()) {
			throw new ArrayIndexOutOfBoundsException(offset);
		}

		int nextOffset = offset;
		int index = Collections.binarySearch(components, new Integer(offset), offsetComparator);
		if (index >= 0) {
			index++;
		}
		else {
			index = -index - 1;
		}
		if (index < components.size()) {
			nextOffset = (components.get(index)).getOffset();
		}
		else {
			nextOffset = getMaxOffset() + 1;
		}
		if ((offset < 0) && (nextOffset > 0)) {
			// Don't allow the new data type to cross from negative into positive stack space.
			nextOffset = 0;
		}
		if ((offset < splitOffset) && (nextOffset > splitOffset)) {
			// Don't allow the new data type to cross from local into parameter stack space.
			nextOffset = splitOffset;
		}
		return nextOffset - offset;
	}

	/**
	 * Returns the default name for the indicated stack offset.
	 * 
	 * @param offset
	 * @return the default stack variable name.
	 */
	public String getDefaultName(DataTypeComponent element) {
		int offset = element.getOffset();
		int paramBaseOffset = getParameterOffset();
		boolean isLocal = growsNegative ? (offset < paramBaseOffset) : (offset >= paramBaseOffset);
		if (isLocal) {
			return SymbolUtilities.getDefaultLocalName(function.getProgram(), offset, 0);
		}
		int index = getParameterIndex(element);
		if (index >= 0) {
			return SymbolUtilities.getDefaultParamName(index);
		}
		return UNKNOWN_PREFIX + Integer.toHexString(Math.abs(offset));
	}

	/**
	 * @param element
	 * @return the index number for this parameter (starting at 1 for the first parameter.) 0 if the
	 *         element is not a parameter.
	 */
	private int getParameterIndex(DataTypeComponent element) {
		int numComps = components.size();
		int firstIndex = -1; // first parameter
		int myIndex = -1; // my parameter
		if (growsNegative) {
			for (int i = numComps - 1; (i >= 0); i--) {
				DataTypeComponent dtc = components.get(i);
				int currentOffset = dtc.getOffset();
				if (currentOffset < splitOffset) {
					break;
				}
				firstIndex = i;
				if (dtc == element) {
					myIndex = i;
				}
			}
			if (myIndex >= 0) {
				return (myIndex - firstIndex);
			}
		}
		else {
			for (int i = 0; (i < numComps); i++) {
				DataTypeComponent dtc = components.get(i);
				int currentOffset = dtc.getOffset();
				if (currentOffset >= splitOffset) {
					break;
				}
				firstIndex = i;
				if (dtc == element) {
					myIndex = i;
				}
			}
			if (myIndex >= 0) {
				return (firstIndex - myIndex);
			}
		}
		return 0;
	}

	/**
	 * Returns true if a stack variable is defined at the specified ordinal.
	 * 
	 * @param ordinal
	 * @return true if variable is defined at ordinal or false if undefined.
	 */
	public boolean isStackVariable(int ordinal) {
		if (ordinal < 0 || ordinal >= getNumComponents()) {
			return false;
		}
		int index = Collections.binarySearch(components, new Integer(ordinal), ordinalComparator);
		if (index >= 0) {
			return true;
		}
		return false;
	}

//	public static void main(String[] args) {
//		StackFrameImpl sf = new StackFrameImpl(0x4);
//		sf.setLocalSize(0xd);
//		sf.setParameterOffset(0x4);
//		sf.setReturnAddressOffset(0x0);
//		sf.createVariable("local_c", new Undefined1(), -0xc, 1);
//		sf.createVariable("local_8", new Undefined4(), -0x8, 4);
//		sf.createVariable("param_4", new DWordDataType(), 0x4, 4);
//		sf.createVariable("param_8", new FloatDataType(), 0x8, 4);
//		StackFrameDataType es = new StackFrameDataType(sf);
//		int numElements = es.getNumComponents();
////		System.out.println("\nElements by ORDINAL");
//		for (int i = 0; i < numElements; i++) {
//			es.getComponent(i);
//		}
////		System.out.println("\nElements by OFFSET");
//		for (int i = es.getMinOffset(); i < es.getMaxOffset(); i++) {
//			es.getComponentAt(i);
//		}
//		System.exit(0);
//	}

}
