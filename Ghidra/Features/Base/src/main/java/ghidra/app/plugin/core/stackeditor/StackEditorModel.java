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
import ghidra.app.plugin.core.compositeeditor.CompositeEditorModel;
import ghidra.app.plugin.core.compositeeditor.CompositeViewerDataTypeManager;
import ghidra.app.plugin.core.stackeditor.StackFrameDataType.StackComponentWrapper;
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

	private Function function;
	private StackFrameDataType originalStackFrameDataType;

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

	@Override
	protected boolean usesAlignedLengthComponents() {
		// NOTE: It is assumed that aligned-length is not used by stack variables
		return false;
	}

	void stackChangedExternally(boolean changed) {
		stackChangedExternally = changed;
		if (changed) {
			setStatus("Stack may have been changed externally -- data may be stale.");
		}
	}

	void load(Function func) {
		function = func;
		originalStackFrameDataType = new StackFrameDataType(function);
		load(originalStackFrameDataType);
	}

	@Override
	public void load(StackFrameDataType dataType) {
		stackChangedExternally(false);
		super.load(dataType);
	}

	@Override
	protected void createViewCompositeFromOriginalComposite() {

		if (viewDTM != null) {
			viewDTM.close();
			viewDTM = null;
		}

		// Establish editor's datatype manager which will manage datatype dependencies.
		viewDTM = new CompositeViewerDataTypeManager<>(originalDTM.getName(), originalDTM);

		// Create a copy of the original stack frame datatype and force the resolving of its
		// datatype dependencies.  A round-about approach is used since the StackFrameDataType
		// itself cannot be resolved and cannot be treated in the same fashion as a normal 
		// Structure edit.  It relies on wrapping a normal structure to serve as a proxy of sorts 
		// for the purpose of managing datatype dependencies.  It is only through the use of
		// a StructureDB that component datatypes are forced to be resolved into the viewDTM.
		// NOTE: Since the StackEditorDataTypeManager keeps a single transaction open unused 
		// datatype pruning is never performed.
		viewComposite = originalComposite.copy(originalDTM);
		originalComposite.resolveWrappedComposite(viewDTM);
		originalComposite = originalStackFrameDataType; // use true original
	}

	@Override
	protected void restoreEditor() {
		throw new UnsupportedOperationException("undo/redo not supported");
	}

	@Override
	public boolean updateAndCheckChangeState() {
		StackFrameDataType sfdt = viewComposite;
		int editReturnAddressOffset = sfdt.getReturnAddressOffset();
		int editLocalSize = sfdt.getLocalSize();
		int editParamOffset = sfdt.getParameterOffset();
		int editParamSize = sfdt.getParameterSize();
		int stackReturnAddressOffset = originalStackFrameDataType.getReturnAddressOffset();
		int stackLocalSize = originalStackFrameDataType.getLocalSize();
		int stackParamOffset = originalStackFrameDataType.getParameterOffset();
		int stackParamSize = originalStackFrameDataType.getParameterSize();
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
		StackComponentWrapper element = viewComposite.getComponent(rowIndex);
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
				return fieldName;
			case COMMENT:
				return element.getComment();
			default:
				return null;
		}
	}

	private String getFieldNameAtRow(int rowIndex, StackFrameDataType stackDt) {
		StackComponentWrapper stackDtc = stackDt.getComponent(rowIndex);
		String fieldName = stackDtc.getFieldName();
		if (fieldName == null) {
			// If the component is a defined stack variable with no name, use default name.
			if (stackDt.isStackVariable(rowIndex)) {
				fieldName = stackDt.getDefaultName(stackDtc);
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
			Object originalValue = getValueAt(rowIndex, modelColumnIndex);
			if (SystemUtilities.isEqual(originalValue, aValue)) {
				return;
			}
			fieldEdited(aValue, rowIndex, modelColumnIndex);
			setSelection(new int[] { rowIndex });
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

		if (currentIndex < 0 || currentIndex >= getRowCount()) {
			return false;
		}

		try {

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
		StackComponentWrapper dtc = viewComposite.getDefinedComponentAtOrdinal(index);
		return dtc != null;
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
			if (startOffset < paramOffset && endOffset >= paramOffset) {
				return false;
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
		if (viewComposite.isDefaultName(newName) && !isOriginalFieldName(newName, rowIndex)) {
			if (Objects.equals(nameInEditor, newName)) {
				return false; // same as current name in the table; do nothing
			}
			throw new InvalidNameException("Cannot set a stack variable name to a default value");
		}

		if (viewComposite.setName(rowIndex, newName)) {
			updateAndCheckChangeState();
			fireTableCellUpdated(rowIndex, getNameColumn());
			notifyCompositeChanged();
			return true;
		}
		return false;
	}

	/** Gets the original field name within the parent data type for a given row in the editor */
	private boolean isOriginalFieldName(String testName, int rowIndex) {
		String fieldName = getFieldNameAtRow(rowIndex, originalStackFrameDataType);
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
		// NOTE: Unused method
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

			Variable[] newVars = viewComposite.getStackVariables();
			List<Variable> newVarsList = Arrays.asList(newVars);
			Collections.sort(newVarsList, StackVariableComparator.get()); // sort for use with getVariableContaining

			StackFrame functionStackFrame = function.getStackFrame();
			functionStackFrame.setLocalSize(viewComposite.getLocalSize());
			functionStackFrame.setReturnAddressOffset(viewComposite.getReturnAddressOffset());

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
					Variable var = functionStackFrame.getVariableContaining(sv.getStackOffset());
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
						if (functionStackFrame.isParameterOffset(sv.getStackOffset()) ||
							(var instanceof Parameter)) {
							// about to make param change - must enable custom storage
							functionStackFrame.getFunction().setCustomVariableStorage(true);
						}
						if (var != null) {
							functionStackFrame.clearVariable(var.getStackOffset());
						}
						newSv = functionStackFrame.createVariable(sv.getName(), sv.getStackOffset(),
							dt, SourceType.USER_DEFINED);
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
			load(function);
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

		fieldEdited(
			DataTypeInstance.getDataTypeInstance(dt, dtLength, usesAlignedLengthComponents()),
			index, getDataTypeColumn());
		setSelection(new int[] { index });
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
		functionChanged(true);
	}

	void functionChanged(boolean isRestore) {

		if (function.isDeleted()) {
			// Close the Editor.
			PluginTool tool = ((StackEditorProvider) provider).getPlugin().getTool();
			tool.setStatusInfo("Stack Editor was closed for " + provider.getName());
			provider.dispose();
			return;
		}

		updateAndCheckChangeState();

		boolean reload = true;
		if (hasChanges) {
			// The user has modified the structure so prompt for whether or
			// not to reload the structure.
			String text = isRestore ? "may have " : "";
			String question = "The function \"" + currentName + "\" " + text +
				"changed outside the editor.\n" + "Discard edits and reload the Stack Editor?";
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
			stackChangedExternally(true);
			refresh();
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

		DataType dataType = viewDTM.getDataType(path.getCategoryPath(), path.getDataTypeName());
		if (dataType == null || !viewDTM.isViewDataTypeFromOriginalDTM(dataType)) {
			return;
		}

		OffsetPairs offsetSelection = getRelOffsetSelection();
		viewDTM.remove(dataType, TaskMonitor.DUMMY);
		fireTableDataChanged();
		componentDataChanged();
		setRelOffsetSelection(offsetSelection);
	}

	@Override
	public void dataTypeRenamed(DataTypeManager dataTypeManager, DataTypePath oldPath,
			DataTypePath newPath) {
		dataTypeMoved(dataTypeManager, oldPath, newPath);
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

		if (oldPath.getDataTypeName().equals(newPath.getDataTypeName())) {
			return;
		}

		// Check for managed datatype changing
		DataType originalDt = originalDTM.getDataType(newPath);
		if (!(originalDt instanceof DatabaseObject)) {
			return;
		}
		DataType dt = viewDTM.findMyDataTypeFromOriginalID(originalDTM.getID(originalDt));
		if (dt == null) {
			return;
		}

		OffsetPairs offsetSelection = getRelOffsetSelection();
		try {
			dt.setName(newPath.getDataTypeName());

			CategoryPath newCategoryPath = newPath.getCategoryPath();
			CategoryPath oldCategoryPath = oldPath.getCategoryPath();
			if (!newCategoryPath.equals(oldCategoryPath)) {
				dt.setCategoryPath(newCategoryPath);
			}
		}
		catch (InvalidNameException | DuplicateNameException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
		fireTableDataChanged();
		componentDataChanged();
		setRelOffsetSelection(offsetSelection);
	}

	@Override
	public void dataTypeChanged(DataTypeManager dataTypeManager, DataTypePath path) {
		if (dataTypeManager != originalDTM) {
			throw new AssertException("Listener only supports original DTM");
		}
		if (!isLoaded()) {
			return;
		}

		DataType changedDt = originalDTM.getDataType(path);
		if (!(changedDt instanceof DatabaseObject)) {
			return;
		}
		DataType viewDt = viewDTM.findMyDataTypeFromOriginalID(originalDTM.getID(changedDt));
		if (viewDt == null) {
			return;
		}

		OffsetPairs offsetSelection = getRelOffsetSelection();
		try {
			viewDTM.replaceDataType(viewDt, changedDt, true);
			viewComposite.checkForStackGrowth();
		}
		catch (DataTypeDependencyException e) {
			throw new AssertException(e);
		}
		compositeInfoChanged(); // size info may have changed
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

		DataType dt = viewDTM.getDataType(oldPath);
		if (dt == null || !viewDTM.isViewDataTypeFromOriginalDTM(dt)) {
			return;
		}

		OffsetPairs offsetSelection = getRelOffsetSelection();
		try {
			viewDTM.replaceDataType(dt, newDataType, true);
			viewComposite.checkForStackGrowth();
		}
		catch (DataTypeDependencyException e) {
			throw new AssertException(e);
		}
		compositeInfoChanged(); // size info may have changed
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

//	@Override
//	public DataTypeInstance validateComponentDataType(int index, String dtString)
//			throws CancelledException, UsrException {
//		DataType dt = null;
//		String dtName = "";
//		dtString = DataTypeHelper.stripWhiteSpace(dtString);
//		if (index < getNumComponents()) {
//			DataTypeComponent element = viewComposite.getComponent(index);
//			dt = element.getDataType();
//			dtName = dt.getDisplayName();
//			if (dtString.equals(dtName)) {
//				return DataTypeInstance.getDataTypeInstance(element.getDataType(),
//					element.getLength(), usesAlignedLengthComponents());
//			}
//		}
//
//		DataType newDt = DataTypeHelper.parseDataType(index, dtString, this, originalDTM,
//			provider.getDtmService());
//
//		if (newDt == null) {
//			if (dt != null) {
//				throw new UsrException("No data type was specified.");
//			}
//			throw new CancelledException();
//		}
//
//		int newLength = newDt.getLength();
//
//		checkIsAllowableDataType(newDt);
//		newDt = resolveDataType(newDt, viewDTM, null);
//		int maxLength = getMaxReplaceLength(index);
//		if (newLength <= 0) {
//			throw new UsrException("Can't currently add this data type--not enough space.");
//		}
//		if (maxLength > 0 && newLength > maxLength) {
//			throw new UsrException(newDt.getDisplayName() + " doesn't fit.");
//		}
//		return DataTypeInstance.getDataTypeInstance(newDt, newLength,
//			usesAlignedLengthComponents());
//	}

	@Override
	protected void deleteComponent(int rowIndex) {
		viewComposite.delete(rowIndex);
		compositeInfoChanged(); // info may have changed
		fireTableDataChanged();
	}

	@Override
	public StackComponentWrapper getComponent(int rowIndex) {
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
