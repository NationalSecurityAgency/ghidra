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

import java.util.*;

import javax.swing.JOptionPane;

import docking.widgets.OptionDialog;
import docking.widgets.fieldpanel.support.FieldRange;
import docking.widgets.fieldpanel.support.FieldSelection;
/**
 * Function stack editor model for maintaining information about the edits to
 * a function stack frame. Updates the stack frame with the edit changes.
 * It also notifies any registered EditorModelListener listeners when
 * the stack frame is changed in the editor.
 * <P>This model provides methods for editing the stack and managing how
 * the changes occur.
 * When edit actions occur and there is a selection, the listener's are notified
 * of the new selection via the listener's overrideSelection method.
 */
import ghidra.app.plugin.core.compositeeditor.*;
import ghidra.app.util.datatype.EmptyCompositeException;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.DatabaseObject;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class StackEditorModel extends CompositeEditorModel<StackFrameDataType> {

	private static final long serialVersionUID = 1L;
	public static final int OFFSET = 0;
	public static final int LENGTH = 1;
	public static final int DATATYPE = 2;
	public static final int NAME = 3;
	public static final int COMMENT = 4;

	private static final int MAX_LOCAL_SIZE = Integer.MAX_VALUE;
	private static final int MAX_PARAM_SIZE = Integer.MAX_VALUE;

	private StackFrame originalStack;

	private boolean stackChangedExternally;

	StackEditorModel(StackEditorProvider provider) {
		super(provider);
		headers = new String[] { "Offset", "Length", "DataType", "Name", "Comment" };
		columnWidths = new int[] { 40, 40, 100, 100, 150 };
		columnOffsets = new int[headers.length];
		adjustOffsets();
		Plugin plugin = provider.getPlugin();
		if (plugin instanceof StackEditorOptionManager) {
			showHexNumbers = ((StackEditorOptionManager) plugin).showStackNumbersInHex();
		}
		else {
			showHexNumbers = true;
		}
	}

	@Override
	public String getTypeName() {
		return "Stack";
	}

	@Override
	protected boolean allowsZeroLengthComponents() {
		return false;
	}

	@Override
	protected boolean allowsBitFields() {
		return false;
	}

	void stackChangedExternally(boolean changed) {
		stackChangedExternally = changed;
	}

	void load(Function function) {
		originalStack = function.getStackFrame();
		ProgramBasedDataTypeManager dtm = function.getProgram().getDataTypeManager();
		StackFrameDataType stackFrameDataType = new StackFrameDataType(originalStack, dtm);
		stackFrameDataType.setCategoryPath(dtm.getRootCategory().getCategoryPath());
		load(stackFrameDataType);
	}

	@Override
	public void load(StackFrameDataType dataType) {
		stackChangedExternally(false);
		super.load(dataType);
	}

	@Override
	protected void createViewCompositeFromOriginalComposite(StackFrameDataType original) {

		if (viewDTM != null) {
			viewDTM.close();
			viewDTM = null;
		}

		// Use temporary standalone view datatype manager which will not manage the viewComposite
		viewDTM = new CompositeViewerDataTypeManager<>(originalDTM.getName(), originalDTM);

		// NOTE: StackFrameDataType cannot be resolved but all of its element datatypes must be
		viewComposite = original.copy(viewDTM);
	}

	@Override
	protected void restoreEditor() {
		throw new UnsupportedOperationException("undo/redo not supported");
	}

	@Override
	public boolean updateAndCheckChangeState() {
		if (originalIsChanging) {
			return false;
		}
		StackFrameDataType sfdt = viewComposite;
		int editReturnAddressOffset = sfdt.getReturnAddressOffset();
		int editLocalSize = sfdt.getLocalSize();
		int editParamOffset = sfdt.getParameterOffset();
		int editParamSize = sfdt.getParameterSize();
		int stackReturnAddressOffset = originalStack.getReturnAddressOffset();
		int stackLocalSize = originalStack.getLocalSize();
		int stackParamOffset = originalStack.getParameterOffset();
		int stackParamSize = originalStack.getParameterSize();
		hasChanges = (editReturnAddressOffset != stackReturnAddressOffset) ||
			(editLocalSize != stackLocalSize) || (editParamOffset != stackParamOffset) ||
			(editParamSize != stackParamSize) || super.updateAndCheckChangeState();
		return hasChanges;
	}

	@Override
	public int getOffsetColumn() {
		return OFFSET;
	}

	@Override
	public int getLengthColumn() {
		return LENGTH;
	}

	@Override
	public int getMnemonicColumn() {
		return -1;
	}

	@Override
	public int getDataTypeColumn() {
		return DATATYPE;
	}

	@Override
	public int getNameColumn() {
		return NAME;
	}

	@Override
	public int getCommentColumn() {
		return COMMENT;
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		if ((viewComposite == null) || (rowIndex >= viewComposite.getNumComponents()) ||
			(rowIndex < 0) || (columnIndex < 0) || (columnIndex >= getColumnCount())) {
			return "";
		}
		DataTypeComponent element = viewComposite.getComponent(rowIndex);
		DataType dt;
		int dtLen;
		switch (columnIndex) {
			case OFFSET:
				int offset = viewComposite.getComponent(rowIndex).getOffset();
				return showHexNumbers ? getHexString(offset, true) : Integer.toString(offset);
			case LENGTH:
				dt = element.getDataType();
				dtLen = dt.getLength();
				String dtHexLen =
					showHexNumbers ? getHexString(dtLen, true) : Integer.toString(dtLen);
				int compLen = element.getLength();
				String compHexLen =
					showHexNumbers ? getHexString(compLen, true) : Integer.toString(compLen);
				if (dtLen >= 0 && dtLen != compLen) {
					return compHexLen + " (needs " + dtHexLen + ")";
				}
				return compHexLen;
			case DATATYPE:
				dt = element.getDataType();
				dtLen = dt.getLength();
				return DataTypeInstance.getDataTypeInstance(dt,
					(dtLen > 0) ? dtLen : element.getLength(), usesAlignedLengthComponents());
			case NAME:
				String fieldName = getFieldNameAtRow(rowIndex, viewComposite);
				if (fieldName == null) {
					fieldName = "";
				}
//				if ((fieldName.length() == 0)
//				 && (element.getOffset() == ((StackFrameDataType)viewComposite).getReturnAddressOffset())) {
//					return "<RETURN_ADDRESS>";
//				}
				return fieldName;
			case COMMENT:
				return element.getComment();
			default:
				return null;
		}
	}

	private String getFieldNameAtRow(int rowIndex, StackFrameDataType stackFrameDataType) {
		DataTypeComponent dataType = stackFrameDataType.getComponent(rowIndex);
		String fieldName = dataType.getFieldName();
		if (fieldName == null) {
			// If the component is a defined stack variable with no name, use default name.
			if (stackFrameDataType.isStackVariable(rowIndex)) {
				fieldName = stackFrameDataType.getDefaultName(dataType);
			}
		}
		return fieldName;
	}

	/**
	 *  This updates one of the values for a component that is a field of
	 *  this data structure.
	 *  @param aValue the new value for the field
	 *  @param rowIndex the component index
	 *  @param modelColumnIndex the model field index within the component
	 */
	@Override
	public void setValueAt(Object aValue, int rowIndex, int modelColumnIndex) {
		try {
			settingValueAt = true;
			OffsetPairs offsetSelection = getRelOffsetSelection();

			Object originalValue = getValueAt(rowIndex, modelColumnIndex);
			if (SystemUtilities.isEqual(originalValue, aValue)) {
				return;
			}

			if (fieldEdited(aValue, rowIndex, modelColumnIndex)) {
				if (modelColumnIndex == OFFSET) {
					int svOffset = Integer.decode((String) aValue).intValue();
					DataTypeComponent dtc =
						(viewComposite).getComponentAt(svOffset);
					offsetSelection = new OffsetPairs();
					offsetSelection.addPair(svOffset, dtc.getEndOffset());
				}
			}
			setRelOffsetSelection(offsetSelection);
		}
		finally {
			settingValueAt = false;
		}
	}

	/**
	 * Gets called to update/validate the current editable location in the table
	 * 
	 * @param value the new cell value
	 * @param rowIndex the row index in the component table
	 * @param columnIndex the column index for the table cell in the current model
	 * @return true if the field was updated or validated successfully
	 */
	@Override
	protected boolean fieldEdited(Object value, int rowIndex, int columnIndex) {
		if (applyingFieldEdit) {
			return true; // the one in progress will indicate any errors.
		}
		try {
			applyingFieldEdit = true;
			switch (columnIndex) {
				case OFFSET:
					setComponentOffset(rowIndex, (String) value);
					break;
				case DATATYPE:
					if (value instanceof StackPieceDataType) {
						return true; // no change
					}
					setComponentDataType(rowIndex, value);
					break;
				case NAME:
					setComponentName(rowIndex, ((String) value).trim());
					break;
				case COMMENT:
					setComponentComment(rowIndex, (String) value);
					break;
				default:
					return false;
			}
			clearStatus();
			return true;
		}
		catch (UsrException e) {
			setStatus(e.getMessage(), true);
			return false;
		}
		finally {
			applyingFieldEdit = false;
		}
	}

	@Override
	public void validateComponentOffset(int index, String offset) throws UsrException {
		try {
			int newOffset = Integer.decode(offset).intValue();
			StackFrameDataType sfdt = viewComposite;
			if ((newOffset < sfdt.getMinOffset()) || (newOffset > sfdt.getMaxOffset())) {
				throw new UsrException(offset + " is not an offset in this stack frame.");
			}

			DataTypeComponent comp = getComponent(index);
			int oldOffset = comp.getOffset();
			int compLength = comp.getLength();
			int start = newOffset;
			int checkLength = compLength;
			if (newOffset == oldOffset) {
				return; // Didn't change offset.
			}
			else if (newOffset < oldOffset) {
				if ((newOffset + compLength) > oldOffset) {
					// Overlaps beginning of where it used to be.
					checkLength = oldOffset - newOffset;
				}
				// Otherwise new one comes before old (no overlap).
			}
			else {
				if (newOffset < (oldOffset + compLength)) {
					// Overlaps end of where it used to be.
					start = oldOffset + compLength;
					checkLength = newOffset - oldOffset;
				}
				// Otherwise new one comes after old (no overlap).
			}

			DataTypeComponent existing = sfdt.getComponentAt(start);
			if (existing == null) {
				if ((start + compLength) > sfdt.getMaxOffset()) {
					throw new InvalidInputException(comp.getDataType().getDisplayName() +
						" doesn't fit in the stack frame when placed at offset " +
						getHexString(newOffset, true) + ".");
				}
				throw new InvalidInputException(comp.getDataType().getDisplayName() +
					" doesn't fit at offset " + getHexString(newOffset, true) + ".");
			}
			if (sfdt.isStackVariable(existing.getOrdinal())) {
				throw new InvalidInputException("There is already a stack variable at offset " +
					getHexString(newOffset, true) + ".");
			}
			int unavailable = newOffset - existing.getOffset();
			int mrl = sfdt.getMaxLength(newOffset) - unavailable;
			if ((mrl != -1) && (checkLength > mrl)) {
				int available = mrl + (compLength - checkLength);
				throw new InvalidInputException(comp.getDataType().getDisplayName() +
					" doesn't fit at offset " + getHexString(newOffset, true) + ". It needs " +
					compLength + " bytes, but " + available + " bytes are available.");
			}
		}
		catch (NumberFormatException nfe) {
			throw new UsrException("\"" + offset + "\" is not a valid offset.");
		}
	}

	public void setComponentOffset(int rowIndex, String value) throws UsrException {
		DataTypeComponent element = viewComposite.getComponent(rowIndex);
		int offset = element.getOffset();
		int svOffset = Integer.decode(value).intValue();
		if (offset == svOffset) {
			return;
		}
		DataTypeComponent newElement = viewComposite.setOffset(rowIndex, svOffset);
		setSelection(new int[] { newElement.getOrdinal() });
		notifyCompositeChanged();
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		if (getNumSelectedRows() > 1) {
			return false;
		}
		if (columnIndex == LENGTH) {
			return false;
		}
		if (rowIndex < 0 || rowIndex >= getRowCount()) {
			return false;
		}
		if (columnIndex < 0 || columnIndex >= getColumnCount()) {
			return false;
		}
		DataTypeComponent dtc = viewComposite.getComponent(rowIndex);
		if (dtc == null) {
			return false;
		}
		boolean notDefined = (viewComposite.getDefinedComponentAtOrdinal(rowIndex) == null);
		return !(notDefined && (columnIndex == OFFSET));
	}

	boolean hasVariableAtOrdinal(int ordinal) {
		if (ordinal < 0 || ordinal >= viewComposite.getNumComponents()) {
			return false;
		}
		return viewComposite.getDefinedComponentAtOrdinal(ordinal) != null;
	}

	boolean hasVariableAtOffset(int offset) {
		return viewComposite.getDefinedComponentAtOffset(offset) != null;
	}

	StackFrame getOriginalStack() {
		return originalStack;
	}

	StackFrameDataType getEditorStack() {
		return viewComposite;
	}

	@Override
	public void clearSelectedComponents() throws UsrException {
		OffsetPairs offsetSelection = getRelOffsetSelection();
		super.clearSelectedComponents();
		setRelOffsetSelection(offsetSelection);
	}

	private OffsetPairs getRelOffsetSelection() {
		OffsetPairs offsets = new OffsetPairs();
		int num = selection.getNumRanges();
		int max = getNumComponents();
		for (int i = 0; i < num; i++) {
			FieldRange range = selection.getFieldRange(i);
			int startOffset = getComponent(range.getStart().getIndex().intValue()).getOffset();
			int endOffset;
			if (range.getEnd().getIndex().intValue() < max) {
				endOffset = getComponent(range.getEnd().getIndex().intValue()).getOffset();
			}
			else {
				endOffset = viewComposite.getPositiveLength() + viewComposite.getParameterOffset();
			}
			offsets.addPair(startOffset, endOffset);
		}
		return offsets;
	}

	private void setRelOffsetSelection(OffsetPairs offsets) {
		FieldSelection newSelection = new FieldSelection();
		int num = offsets.getNumPairs();
		int min = viewComposite.getMinOffset();
		int max = viewComposite.getMaxOffset();
		for (int i = 0; i < num; i++) {
			XYPair pair = offsets.getPair(i);
			if ((pair.y < min) || (pair.x > max)) {
				continue;
			}
			int x = (pair.x < min) ? min : pair.x;
			int y = (pair.y > max) ? max + 1 : pair.y;

			DataTypeComponent startDtc = viewComposite.getComponentAt(x);
			DataTypeComponent endDtc = viewComposite.getComponentAt(y - 1);
			if (startDtc == null || endDtc == null) {
				return;
			}
			int startIndex = startDtc.getOrdinal();
			int endIndex;
			if (y <= max) {
				endIndex = endDtc.getOrdinal();
				if (endDtc.getOffset() != y) {
					endIndex++;
				}
			}
			else {
				endIndex = viewComposite.getNumComponents();
			}
			newSelection.addRange(startIndex, endIndex);
		}
		setSelection(newSelection);
	}

	private class OffsetPairs {
		ArrayList<XYPair> pairs;

		OffsetPairs() {
			pairs = new ArrayList<>();
		}

		void addPair(int x, int y) {
			pairs.add(new XYPair(x, y));
		}

		int getNumPairs() {
			return pairs.size();
		}

		XYPair getPair(int i) {
			if (i >= 0 && i < pairs.size()) {
				return pairs.get(i);
			}
			return null;
		}
	}

	private class XYPair {
		int x;
		int y;

		XYPair(int x, int y) {
			this.x = x;
			this.y = y;
		}
	}

	void setLocalSize(int size) throws UsrException {
		if (getLocalSize() == size) {
			return;
		}
		if (size > MAX_LOCAL_SIZE) {
			throw new UsrException(
				"Local size cannot exceed 0x" + Integer.toHexString(MAX_LOCAL_SIZE) + ".");
		}
		viewComposite.setLocalSize(size);
		notifyCompositeChanged();
	}

	void setParameterSize(int size) throws UsrException {
		if (getParameterSize() == size) {
			return;
		}
		if (size > MAX_PARAM_SIZE) {
			throw new UsrException(
				"Parameter size cannot exceed 0x" + Integer.toHexString(MAX_PARAM_SIZE) + ".");
		}
		viewComposite.setParameterSize(size);
		notifyCompositeChanged();
	}

	int getFrameSize() {
		return viewComposite.getFrameSize();
	}

	int getLocalSize() {
		return viewComposite.getLocalSize();
	}

	int getParameterSize() {
		return viewComposite.getParameterSize();
	}

	int getParameterOffset() {
		return viewComposite.getParameterOffset();
	}

	int getReturnAddressOffset() {
		return viewComposite.getReturnAddressOffset();
	}

	@Override
	public int getMaxAddLength(int index) {
		return getMaxReplaceLength(index);
	}

	@Override
	public int getMaxReplaceLength(int currentIndex) {
		int offset = viewComposite.getComponent(currentIndex).getOffset();
		return viewComposite.getMaxLength(offset);
	}

	@Override
	public int getMaxDuplicates(int rowIndex) {
		return 0;
	}

	@Override
	public boolean isAddAllowed(DataType dataType) {
		if (isSingleRowSelection()) {
			return isAddAllowed(getMinIndexSelected(), dataType);
		}
		return false;
	}

	/**
	 * Returns whether or not addition of the specified component is allowed
	 * at the specified index. the addition could be an insert or replace as
	 * determined by the state of the edit model.
	 *
	 * @param currentIndex index of the component in the structure.
	 * @param dataType the data type to be inserted.
	 */
	@Override
	public boolean isAddAllowed(int currentIndex, DataType dataType) {
		try {
			if (currentIndex < 0 || currentIndex >= getRowCount()) {
				return false;
			}
			checkIsAllowableDataType(dataType);
		}
		catch (InvalidDataTypeException e) {
			return false;
		}

		DataTypeComponent comp = getComponent(currentIndex);
		DataType compDt = comp.getDataType();
		boolean existingPointer = (compDt instanceof Pointer);
		boolean isPointer = (dataType instanceof Pointer) || existingPointer;
		int newLength = dataType.getLength();
		// NOTE : Allow the generic pointer, but don't allow -1 length data
		//        types (i.e. string) except on pointers.
		if (!isPointer && (newLength <= 0)) {
			return false;
		}
		if (existingPointer) {
			newLength = compDt.getLength();
		}
		int offset = comp.getOffset();
// TODO: not sure we need to prevent creating local variables in 'save' area,
//       since doing so just leads to confusion when using stack frame editor
//		if (((StackFrameDataType) viewComposite).growsNegative()) {
//			if (offset >= 0 && offset < getParameterOffset()) {
//				return false;
//			}
//		}
//		else {
//			if (offset < 0 && offset > getParameterOffset()) {
//				return false;
//			}
//		}
		int maxBytes = viewComposite.getMaxLength(offset);
		if (newLength > maxBytes) {
			return false;
		}
		return true;
	}

	@Override
	public boolean isBitFieldAllowed() {
		return false;
	}

	@Override
	public boolean isArrayAllowed() {
		if (getNumSelectedRows() != 1 || viewComposite == null) {
			return false;
		}
		int index = getMinIndexSelected();
		if (index < 0 || index >= viewComposite.getNumComponents()) {
			return false;
		}
		return viewComposite.getDefinedComponentAtOrdinal(index) != null;
	}

	@Override
	public boolean isClearAllowed() {
		return (getNumSelectedRows() > 0);
	}

	@Override
	public boolean isDeleteAllowed() {
		if (selection.getNumRanges() != 1) {
			return false;
		}
		FieldRange range = selection.getFieldRange(0);
		if (range.getStart().getIndex().intValue() == 0 ||
			range.getEnd().getIndex().intValue() == getRowCount()) {
			// Can't cross zero boundary.
			int startOffset = getComponent(range.getStart().getIndex().intValue()).getOffset();
			int endOffset = getComponent(range.getEnd().getIndex().intValue() - 1).getEndOffset();
			if (startOffset < 0 && endOffset >= 0) {
				return false;
			}
			int paramOffset = getParameterOffset();
			if (paramOffset >= 0) {
				// grows negative
				if (startOffset < paramOffset && endOffset >= paramOffset) {
					return false;
				}
			}
			else {
				// grows positive
				if (startOffset <= paramOffset && endOffset > paramOffset) {
					return false;
				}
			}
			return true;
		}
		return false;
	}

	@Override
	public boolean isReplaceAllowed(int currentIndex, DataType dataType) {
		// NOTE : Don't allow -1 length data types (i.e. string).
		if (!(dataType instanceof Pointer) && (dataType.getLength() <= 0)) {
			return false;
		}
		try {
			if (currentIndex < 0 || currentIndex >= getRowCount()) {
				return false;
			}
			checkIsAllowableDataType(dataType);
		}
		catch (InvalidDataTypeException e) {
			return false;
		}
		int offset = getComponent(currentIndex).getOffset();
		int maxBytes = viewComposite.getMaxLength(offset);
		if (dataType.getLength() > maxBytes) {
			return false;
		}
		return true;
	}

	private void adjustComponents(DataType dataType) {
		DataTypeComponent[] comps = viewComposite.getDefinedComponents();
		String msg = "";
		for (DataTypeComponent component : comps) {
			DataType compDt = component.getDataType();
			if (compDt == dataType) {
				int len = compDt.getLength();
				if (len <= 0) {
					len = component.getLength();
				}
				try {
					viewComposite.replace(component.getOrdinal(), compDt, len,
						component.getFieldName(),
						component.getComment());
				}
				catch (IllegalArgumentException e) {
					msg += "Adjusting variable at offset " +
						getHexString(component.getOffset(), true) + ". " + e.getMessage() + "\n";
				}
			}
		}
		if (msg.length() > 0) {
			JOptionPane.showMessageDialog(provider.getComponent(), msg,
				"Stack Editor Adjustment Warning", JOptionPane.WARNING_MESSAGE);
		}
	}

	private void replaceComponents(DataType oldDataType, DataType newDataType) {
		DataTypeComponent[] comps = viewComposite.getDefinedComponents();
		String msg = "";
		for (DataTypeComponent component : comps) {
			DataType compDt = component.getDataType();
			if (compDt == oldDataType) {
				int len = newDataType.getLength();
				if (len <= 0) {
					len = component.getLength();
				}
				try {
					viewComposite.replace(component.getOrdinal(), newDataType, len,
						component.getFieldName(), component.getComment());
				}
				catch (IllegalArgumentException e) {
					msg += "Replacing variable at offset " +
						getHexString(component.getOffset(), true) + ". " + e.getMessage() + "\n";
				}
			}
		}
		if (msg.length() > 0) {
			JOptionPane.showMessageDialog(provider.getComponent(), msg,
				"Stack Editor Replacement Warning", JOptionPane.WARNING_MESSAGE);
		}
	}

	@Override
	public void setComponentDataTypeInstance(int index, DataType dt, int length)
			throws UsrException {
		checkIsAllowableDataType(dt);
		viewComposite.setDataType(index, dt, length);
	}

	@Override
	public void validateComponentName(int currentIndex, String name) throws UsrException {
		if (SymbolUtilities.containsInvalidChars(name)) {
			throw new InvalidInputException(
				"Symbol name \"" + name + "\"contains invalid characters.");
		}
	}

	@Override
	public boolean setComponentName(int rowIndex, String newName) throws InvalidNameException {

		if (newName.trim().length() == 0) {
			newName = null;
		}

		// prevent user names that are default values, unless the value is the original name
		String nameInEditor = (String) getValueAt(rowIndex, NAME);
		StackFrameDataType stackFrameDataType = viewComposite;
		if (stackFrameDataType.isDefaultName(newName) && !isOriginalFieldName(newName, rowIndex)) {
			if (Objects.equals(nameInEditor, newName)) {
				return false; // same as current name in the table; do nothing
			}
			throw new InvalidNameException("Cannot set a stack variable name to a default value");
		}

		if (stackFrameDataType.setName(rowIndex, newName)) {
			updateAndCheckChangeState();
			fireTableCellUpdated(rowIndex, getNameColumn());
			notifyCompositeChanged();
			return true;
		}
		return false;
	}

	/** Gets the original field name within the parent data type for a given row in the editor */
	private boolean isOriginalFieldName(String testName, int rowIndex) {
		StackFrameDataType dataType = getOriginalComposite();
		String fieldName = getFieldNameAtRow(rowIndex, dataType);
		return SystemUtilities.isEqual(fieldName, testName);
	}

	@Override
	public boolean setComponentComment(int currentIndex, String comment) {
		if (viewComposite.setComment(currentIndex, comment)) {
			updateAndCheckChangeState();
			fireTableRowsUpdated(currentIndex, currentIndex);
			componentDataChanged();
			return true;
		}
		return false;
	}

	@Override
	public DataTypeComponent add(DataType dataType) throws UsrException {
		int rowIndex = getMinIndexSelected();
		if (rowIndex < 0) {
			throw new UsrException("A component must be selected.");
		}
		return replace(rowIndex, dataType);
	}

	/**
	 * Adds the specified data type at the specified component index. Whether
	 * an insert or replace occurs depends on whether the indicated index is
	 * in a selection and whether in locked or unlocked mode.
	 *
	 * @param index the component index of where to add the data type.
	 * @param dt the data type to add
	 *
	 * @return true if the component is added, false if it doesn't.
	 * @throws UsrException if add fails
	 */
	@Override
	public DataTypeComponent add(int index, DataType dt) throws UsrException {
		return replace(index, dt);
	}

	@Override
	public DataTypeComponent add(int index, DataType dt, int dtLength) throws UsrException {
		return replace(index, dt, dtLength);
	}

	private Variable getVariableContaining(int offset, List<Variable> sortedVariables) {
		Object key = offset;
		int index = Collections.binarySearch(sortedVariables, key, StackVariableComparator.get());
		if (index >= 0) {
			return sortedVariables.get(index);
		}
		index = -index - 1;
		index = index - 1;
		if (index < 0) {
			return null;
		}
		Variable var = sortedVariables.get(index);
		int stackOffset = var.getStackOffset();
		if ((stackOffset + var.getLength()) > offset) {
			if (var.getDataType().isDeleted()) {
				sortedVariables.remove(index);
			}
			else {
				return var;
			}
		}
		return null;
	}

	@Override
	public boolean apply() throws EmptyCompositeException, InvalidDataTypeException {

		// commit changes for any fields under edit
		if (isEditingField()) {
			endFieldEditing();
		}

		clearStatus();

		if (avoidApplyingConflictingData()) {
			return false;
		}

		OffsetPairs offsetSelection = getRelOffsetSelection();
		int transID = startTransaction("Apply \"" + getCompositeName() + "\" Stack Edits");
		try {
			if (!isValidName() || !hasChanges()) {
				return false;
			}
			StackFrame original = getOriginalStack(); // FIXME: Not Needed - use originalStack
			Function function = original.getFunction();
			StackFrameDataType edited = getEditorStack();

			Variable[] newVars = edited.getStackVariables();
			List<Variable> newVarsList = Arrays.asList(newVars);
			Collections.sort(newVarsList, StackVariableComparator.get()); // sort for use with getVariableContaining

			original.setLocalSize(edited.getLocalSize());
			original.setReturnAddressOffset(edited.getReturnAddressOffset());

			// first-pass: remove deleted params from end of param list if possible
			// to avoid custom storage enablement
			Parameter[] origParams = function.getParameters();
			for (int i = origParams.length - 1; i >= 0; --i) {

				Parameter p = origParams[i];
				if (!p.hasStackStorage() || p.isAutoParameter()) {
					break;
				}
				int offset = (int) p.getVariableStorage().getLastVarnode().getAddress().getOffset();
				if (getVariableContaining(offset, newVarsList) == null) {
					p.getSymbol().delete();
				}
				else {
					break; // quit on first in-bound param
				}
			}

			// second-pass: remove deleted locals/params from stack frame,
			// this will impose custom storage if any params removed this way
			for (Variable var : function.getAllVariables()) {
				if (!var.hasStackStorage() || (var.getSymbol() == null)) {
					continue;
				}
				int offset =
					(int) var.getVariableStorage().getLastVarnode().getAddress().getOffset();
				if (getVariableContaining(offset, newVarsList) == null) {
					if ((var instanceof Parameter) && !function.hasCustomVariableStorage()) {
						// force custom storage to prevent param shift
						function.setCustomVariableStorage(true);
					}
					var.getSymbol().delete();
				}
			}

			for (Variable sv : newVars) {
				Variable newSv = null;
				try {
					DataType dt = originalDTM.resolve(sv.getDataType(), null);
					Variable var = original.getVariableContaining(sv.getStackOffset());
// TODO: Handle case where new size is smaller but stack alignment will prevent variable shuffle on setDataType - could be problamatic
					if (var != null && var.getStackOffset() == sv.getStackOffset() &&
						var.getLength() == sv.getLength()) {
						newSv = var;
						if (!newSv.getName().equals(sv.getName())) {
							newSv.setName(sv.getName(), SourceType.USER_DEFINED);
						}
						if (!dt.equals(newSv.getDataType())) {
							newSv.setDataType(dt, SourceType.USER_DEFINED);
						}
					}
					else {
						if (original.isParameterOffset(sv.getStackOffset()) ||
							(var instanceof Parameter)) {
							// about to make param change - must enable custom storage
							original.getFunction().setCustomVariableStorage(true);
						}
						if (var != null) {
							original.clearVariable(var.getStackOffset());
						}
						newSv = original.createVariable(sv.getName(), sv.getStackOffset(), dt,
							SourceType.USER_DEFINED);
					}
					newSv.setComment(sv.getComment());
				}
				catch (DuplicateNameException e) {
					Msg.showError(this, null, "Stack Edit Error",
						"Stack variable error at offset " + sv.getStackOffset() + ": " +
							e.getMessage());
					continue;
				}
				catch (InvalidInputException e) {
					Msg.showError(this, null, "Stack Edit Error",
						"Stack variable error at offset " + sv.getStackOffset() + ": " +
							e.getMessage());
					continue;
				}
				String comment = sv.getComment();
				if (comment != null) {
					newSv.setComment(comment);
				}
			}
			load(new StackFrameDataType(original, originalDTM));
			clearStatus();
			return true;
		}
		finally {
			endTransaction(transID);
			setRelOffsetSelection(offsetSelection);
		}
	}

	private boolean avoidApplyingConflictingData() {
		if (!hasChanges()) {
			return true; // nothing to do (probably can't get here)
		}

		if (!stackChangedExternally) {
			return false; // not conflicts; nothing to avoid
		}

		int choice = OptionDialog.showOptionDialogWithCancelAsDefaultButton(provider.getComponent(),
			"Overwrite Program Changes?",
			"<html>The function's stack data has changed outside of this<br>" +
				"Stack Editor Provider.<br><BR>" +
				"Would you like to overwrite the external changes with your changes?",
			"Overwrite", OptionDialog.WARNING_MESSAGE);

		if (choice == OptionDialog.CANCEL_OPTION) {
			return true;
		}

		return false;
	}

	protected int startTransaction(String startMsg) {
		Program program = ((StackEditorProvider) provider).getProgram();
		if (program != null) {
			return program.startTransaction(startMsg);
		}
		return -1;
	}

	protected void endTransaction(int transID) {
		Program program = ((StackEditorProvider) provider).getProgram();
		if (program != null) {
			program.endTransaction(transID, true);
		}
	}

	@Override
	public void duplicateMultiple(int index, int multiple, TaskMonitor monitor)
			throws UsrException {
		// do nothing
	}

	@Override
	public DataTypeComponent insert(DataType dataType) throws UsrException {
		return null;
	}

	@Override
	public DataTypeComponent insert(int index, DataType dataType) throws UsrException {
		return null;
	}

	@Override
	public DataTypeComponent insert(int index, DataType dt, int dtLength) throws UsrException {
		return null;
	}

	@Override
	public boolean moveUp() {
		return false;
	}

	@Override
	public boolean moveDown() {
		return false;
	}

	public DataTypeComponent replace(DataType dataType) throws UsrException {
		int rowIndex = getMinIndexSelected();
		if (rowIndex < 0) {
			throw new UsrException("A component must be selected.");
		}
		return replace(rowIndex, dataType);
	}

	private DataTypeComponent replace(int index, DataType dataType) throws UsrException {
		try {
			DataTypeInstance dti = getDropDataType(index, dataType);
			return replace(index, dti.getDataType(), dti.getLength());
		}
		catch (CancelledException e) {
			return null;
		}
	}

	@Override
	public DataTypeComponent replace(int index, DataType dt, int dtLength) throws UsrException {

		OffsetPairs offsetSelection = getRelOffsetSelection();
		fieldEdited(
			DataTypeInstance.getDataTypeInstance(dt, dtLength, usesAlignedLengthComponents()),
			index, getDataTypeColumn());
		setRelOffsetSelection(offsetSelection);
		return getComponent(index);
	}

	@Override
	public int getMaxElements() {
		if (getNumSelectedComponentRows() != 1) {
			return 0;
		}
		int index = getMinIndexSelected();
		if (index < 0 || index >= viewComposite.getNumComponents()) {
			setStatus("Can only create arrays on a defined stack variable.", true);
			return 0;
		}
		DataTypeComponent dtc = viewComposite.getDefinedComponentAtOrdinal(index);
		if (dtc == null) {
			setStatus("Can only create arrays on a defined stack variable.", true);
			return 0;
		}
		int max = getMaxReplaceLength(index);
		if (max == Integer.MAX_VALUE) {
			return Integer.MAX_VALUE;
		}
		// Arrays currently use aligned-length only
		return max / dtc.getDataType().getAlignedLength();
	}

	@Override
	public void restored(DataTypeManager dataTypeManager) {

		StackFrameDataType sfdt = getOriginalComposite();
		Function function = sfdt.getFunction();
		if (function.isDeleted()) {
			// Cancel Editor.
			provider.dispose();
			PluginTool tool = ((StackEditorProvider) provider).getPlugin().getTool();
			tool.setStatusInfo("Stack Editor was closed for " + provider.getName());
			return;
		}

		updateAndCheckChangeState();

		boolean reload = true;
		if (hasChanges) {
			// The user has modified the structure so prompt for whether or
			// not to reload the structure.
			String question = "The program \"dtm.getName()\" has been restored.\n" + "\"" +
				currentName + "\" may have changed outside the editor.\n" +
				"Discard edits and reload the Stack Editor?";
			String title = "Reload Stack Editor?";
			int response = OptionDialog
					.showYesNoDialogWithNoAsDefaultButton(provider.getComponent(), title, question);
			if (response != 1) {
				reload = false;
			}
		}
		if (reload) {
			load(function);
		}
		else {
			refresh();
		}
	}

	@Override
	public void dataTypeChanged(DataTypeManager dataTypeManager, DataTypePath path) {
		if (dataTypeManager != originalDTM) {
			throw new AssertException("Listener only supports original DTM");
		}
		if (!isLoaded()) {
			return;
		}
		DataType dataType = dataTypeManager.getDataType(path);
		OffsetPairs offsetSelection = getRelOffsetSelection();
		adjustComponents(dataType);
		fireTableDataChanged();
		componentDataChanged();
		setRelOffsetSelection(offsetSelection);
	}

	@Override
	public void dataTypeMoved(DataTypeManager dataTypeManager, DataTypePath oldPath,
			DataTypePath newPath) {
		if (dataTypeManager != originalDTM) {
			throw new AssertException("Listener only supports original DTM");
		}
		if (!isLoaded()) {
			return;
		}
		if (originalDataTypePath != null &&
			originalDataTypePath.getDataTypeName().equals(newPath.getDataTypeName()) &&
			originalDataTypePath.getCategoryPath().equals(oldPath.getCategoryPath())) {
			originalDataTypePath = newPath;
			compositeInfoChanged();
		}
	}

	@Override
	public void dataTypeRemoved(DataTypeManager dataTypeManager, DataTypePath path) {
		if (dataTypeManager != originalDTM) {
			throw new AssertException("Listener only supports original DTM");
		}
		if (!isLoaded()) {
			return;
		}
		OffsetPairs offsetSelection = getRelOffsetSelection();
		DataType dataType = dataTypeManager.getDataType(path);
		replaceComponents(dataType, DataType.DEFAULT);
		fireTableDataChanged();
		componentDataChanged();
		setRelOffsetSelection(offsetSelection);
	}

	@Override
	public void dataTypeRenamed(DataTypeManager dataTypeManager, DataTypePath oldPath,
			DataTypePath newPath) {
		if (dataTypeManager != originalDTM) {
			throw new AssertException("Listener only supports original DTM");
		}
		if (!isLoaded()) {
			return;
		}

		DataTypePath originalPath = getOriginalDataTypePath();
		if (originalPath == null || !oldPath.equals(originalPath)) {
			return;
		}

		// Don't try to actually rename, since we shouldn't get name change on a
		// fabricated stack data type.
		OffsetPairs offsetSelection = getRelOffsetSelection();
		fireTableDataChanged();
		componentDataChanged();
		setRelOffsetSelection(offsetSelection);
	}

	@Override
	public void dataTypeReplaced(DataTypeManager dataTypeManager, DataTypePath oldPath,
			DataTypePath newPath, DataType newDataType) {
		if (dataTypeManager != originalDTM) {
			throw new AssertException("Listener only supports original DTM");
		}
		if (!isLoaded()) {
			return;
		}
		DataType oldDataType = viewDTM.getDataType(oldPath);
		OffsetPairs offsetSelection = getRelOffsetSelection();
		replaceComponents(oldDataType, newDataType);
		fireTableDataChanged();
		componentDataChanged();
		setRelOffsetSelection(offsetSelection);
	}

	@Override
	protected StackFrameDataType getOriginalComposite() {
		return originalComposite;
	}

	@Override
	protected boolean originalCompositeExists() {
		return false;
	}

	@Override
	protected DataTypeManager getOriginalDataTypeManager() {
		// This is to allow the stack editor panel to have access.
		return super.getOriginalDataTypeManager();
	}

	@Override
	protected long getCompositeID() {
		// This is to allow the stack editor panel to have access.
		return super.getCompositeID();
	}

	protected void refresh() {
		if (isLoaded()) {
			OffsetPairs offsetSelection = getRelOffsetSelection();
			refreshComponents();
			fireTableDataChanged();
			componentDataChanged();
			compositeInfoChanged();
			setRelOffsetSelection(offsetSelection);
		}
	}

	private void refreshComponents() {
		DataTypeComponent[] comps = viewComposite.getDefinedComponents();
		for (int i = comps.length - 1; i >= 0; i--) {
			DataTypeComponent component = comps[i];
			DataType compDt = component.getDataType();
			if (compDt instanceof DatabaseObject) {
				// NOTE: viewDTM only maps view-to-original IDs for DataTypeDB
				long myId = viewDTM.getID(compDt);
				if (viewDTM.findOriginalDataTypeFromMyID(myId) == null) {
					// Datatype not found
					clearComponent(component.getOrdinal());
				}
			}
		}

		viewDTM.refreshDBTypesFromOriginal();
	}

	@Override
	protected void clearComponents(int[] rows) {
		for (int i = rows.length - 1; i >= 0; i--) {
			viewComposite.clearComponent(rows[i]);
		}
		notifyCompositeChanged();
	}

	//**************************************************************************
	// The methods below were overridden to prevent data types with a length of
	// -1 from being applied in the stack editor. We also don't want to get
	// prompted for a length when the user tries to apply a -1 length data type.
	//**************************************************************************
	//vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv

	@Override
	public DataTypeInstance validateComponentDataType(int index, String dtString)
			throws CancelledException, UsrException {
		DataType dt = null;
		String dtName = "";
		dtString = DataTypeHelper.stripWhiteSpace(dtString);
		if (index < getNumComponents()) {
			DataTypeComponent element = viewComposite.getComponent(index);
			dt = element.getDataType();
			dtName = dt.getDisplayName();
			if (dtString.equals(dtName)) {
				return DataTypeInstance.getDataTypeInstance(element.getDataType(),
					element.getLength(), usesAlignedLengthComponents());
			}
		}

		DataType newDt = DataTypeHelper.parseDataType(index, dtString, this, originalDTM,
			provider.getDtmService());

		if (newDt == null) {
			if (dt != null) {
				throw new UsrException("No data type was specified.");
			}
			throw new CancelledException();
		}

		int newLength = newDt.getLength();

		checkIsAllowableDataType(newDt);
		newDt = resolveDataType(newDt, viewDTM, null);
		int maxLength = getMaxReplaceLength(index);
		if (newLength <= 0) {
			throw new UsrException("Can't currently add this data type--not enough space.");
		}
		if (maxLength > 0 && newLength > maxLength) {
			throw new UsrException(newDt.getDisplayName() + " doesn't fit.");
		}
		return DataTypeInstance.getDataTypeInstance(newDt, newLength,
			usesAlignedLengthComponents());
	}

	@Override
	protected void deleteComponent(int rowIndex) {
		viewComposite.delete(rowIndex);
	}

	@Override
	public DataTypeComponent getComponent(int rowIndex) {
		if (viewComposite == null) {
			return null;
		}
		return viewComposite.getComponent(rowIndex);
	}

	@Override
	public int getNumComponents() {
		if (viewComposite == null) {
			return 0;
		}
		return viewComposite.getNumComponents();
	}

	@Override
	public boolean isShowingUndefinedBytes() {
		return true;
	}

	//^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
}
