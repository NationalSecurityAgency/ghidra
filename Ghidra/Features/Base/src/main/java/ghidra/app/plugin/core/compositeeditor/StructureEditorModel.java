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
package ghidra.app.plugin.core.compositeeditor;

import java.math.BigInteger;
import java.util.*;

import javax.swing.table.TableColumn;

import docking.widgets.OptionDialog;
import docking.widgets.dialogs.InputDialog;
import docking.widgets.dialogs.InputDialogListener;
import docking.widgets.fieldpanel.support.FieldRange;
import docking.widgets.fieldpanel.support.FieldSelection;
import docking.widgets.table.GTableHeaderRenderer;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.InsufficientBytesException;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

class StructureEditorModel extends CompEditorModel {

	private static final long serialVersionUID = 1L;
	private static final int OFFSET = 0;
	private static final int LENGTH = 1;
	private static final int MNEMONIC = 2;
	private static final int DATATYPE = 3;
	private static final int FIELDNAME = 4;
	private static final int COMMENT = 5;
	private static final int ORDINAL = 6;

	private List<TableColumn> hiddenColumns;

	StructureEditorModel(StructureEditorProvider provider, boolean showHexNumbers) {
		super(provider);
		headers = new String[] { "Offset", "Length", "Mnemonic", "DataType", "Name", "Comment" };
		columnWidths = new int[] { 75, 75, 100, 100, 100, 150 };
		columnOffsets = new int[headers.length];
		adjustOffsets();
		this.showHexNumbers = showHexNumbers;

		List<TableColumn> additionalColumns = new ArrayList<>();
		TableColumn ordinalColumn = new TableColumn(ORDINAL, 75);
		ordinalColumn.setHeaderRenderer(new GTableHeaderRenderer());
		ordinalColumn.setHeaderValue("Ordinal");
		additionalColumns.add(ordinalColumn);
		hiddenColumns = Collections.unmodifiableList(additionalColumns);
	}

	@Override
	public String getTypeName() {
		return "Structure";
	}

	@Override
	protected List<TableColumn> getHiddenColumns() {
		return hiddenColumns;
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
		return MNEMONIC;
	}

	@Override
	public int getDataTypeColumn() {
		return DATATYPE;
	}

	@Override
	public int getNameColumn() {
		return FIELDNAME;
	}

	@Override
	public int getCommentColumn() {
		return COMMENT;
	}

	/**
	 * Returns the number of component rows in the viewer. There may be a
	 * blank row at the end for selecting. Therefore this number can be
	 * different than the actual number of components currently in the
	 * structure being viewed.
	 *
	 * @return the number of rows in the model
	 */
	@Override
	public int getRowCount() {
		int componentCount = getNumComponents();
		int rowCount = componentCount + 1; // add blank edit row
		return rowCount;
	}

	/**
	 * Returns an attribute value for the cell at <I>columnIndex</I>
	 * and <I>rowIndex</I>.
	 *
	 * @param	rowIndex	the row whose value is to be looked up
	 * @param	columnIndex 	the column whose value is to be looked up
	 * @return	the value Object at the specified cell
	 */
	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {

		if ((viewComposite == null) || (rowIndex < 0) || (columnIndex < 0)) {
			return "";
		}

		DataTypeComponent dtc = getComponent(rowIndex);
		if (dtc == null) {
			if (columnIndex == getDataTypeColumn()) {
				return null;
			}
			return "";
		}

		String value = null;
		if (columnIndex == getOffsetColumn()) {
			int offset = dtc.getOffset();
			value = showHexNumbers ? getHexString(offset, true) : Integer.toString(offset);
		}
		else if (columnIndex == getLengthColumn()) {
			int compLen = dtc.getLength();
			value = showHexNumbers ? getHexString(compLen, true) : Integer.toString(compLen);
		}
		else if (columnIndex == getMnemonicColumn()) {
			DataType dt = dtc.getDataType();
			value = dt.getMnemonic(dtc.getDefaultSettings());
			int compLen = dtc.getLength();
			int dtLen = dt.isZeroLength() ? 0 : dt.getLength();
			if (dtLen > compLen) {
				value = "TooBig: " + value + " needs " + dtLen + " has " + compLen;
			}
		}
		else if (columnIndex == getDataTypeColumn()) {
			DataType dt = dtc.getDataType();
			int dtLen = dt.getLength();
			return DataTypeInstance.getDataTypeInstance(dt, (dtLen > 0) ? dtLen : dtc.getLength(),
				usesAlignedLengthComponents());
		}
		else if (columnIndex == getNameColumn()) {
			value = dtc.getFieldName();
		}
		else if (columnIndex == getCommentColumn()) {
			value = dtc.getComment();
		}
		else if (columnIndex == ORDINAL) {
			int ordinal = dtc.getOrdinal();
			value = showHexNumbers ? getHexString(ordinal, true) : Integer.toString(ordinal);
		}

		return (value == null) ? "" : value;
	}

	@Override
	public DataTypeComponent getComponent(int rowIndex) {
		int numComponents = getNumComponents();
		if (rowIndex < 0 || rowIndex == numComponents) {
			return null;
		}
		Structure viewStruct = (Structure) viewComposite;
		if (rowIndex > numComponents) {
			return null;
		}
		if (isShowingUndefinedBytes()) {
			return viewComposite.getComponent(rowIndex);
		}
		DataTypeComponent[] definedComponents = viewStruct.getDefinedComponents();
		return definedComponents[rowIndex];
	}

	@Override
	public int getNumComponents() {
		return viewComposite == null ? 0 : viewComposite.getNumComponents();
	}

	@Override
	protected boolean isSizeEditable() {
		return !isPackingEnabled();
	}

	void setStructureSize(int size) {
		if (viewComposite == null || viewComposite.isPackingEnabled()) {
			return;
		}
		int currentLength = (viewComposite.isZeroLength()) ? 0 : viewComposite.getLength();
		if (currentLength == size) {
			return;
		}

		viewDTM.withTransaction("Set Size", () -> {
			Structure structure = (Structure) viewComposite;
			structure.setLength(size);
		});
		notifyCompositeChanged();
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		if (getNumSelectedRows() != 1) {
			return false;
		}
		if ((rowIndex < 0) || (rowIndex >= getRowCount())) {
			return false;
		}

		switch (columnIndex) {
			case DATATYPE:
				return true;
			case FIELDNAME:
			case COMMENT:
				DataTypeComponent dtc = getComponent(rowIndex);
				if (dtc == null) {
					return false;
				}
				DataType dt = dtc.getDataType();
				if (dt == DataType.DEFAULT) {
					return false;
				}
				return true;
			default:
				return false; // User can't edit any other fields.
		}
	}

	@Override
	public void clearSelectedComponents() throws UsrException {
		if (!isClearAllowed()) {
			throw new UsrException("Clearing is not allowed.");
		}
		// If we are on the selection then clear all selected.
		if (this.getNumSelectedComponentRows() <= 0) {
			throw new UsrException("Only selections can be cleared.");
		}
		clearComponents(getSelectedComponentRows());
	}

	@Override
	public void clearComponents(int[] indices) {
		if (isEditingField()) {
			endFieldEditing();
		}

		Arrays.sort(indices);

		// work from back to front so our indices aren't affected by each component's clear.
		viewDTM.withTransaction("Clear Components", () -> {
			for (int i = indices.length - 1; i >= 0; i--) {
				DataTypeComponent comp = getComponent(indices[i]);
				if (comp == null) {
					continue; // must be on blank last line.
				}
				boolean isSelected = selection.containsEntirely(BigInteger.valueOf(indices[i]));
				int numBytes = comp.getLength();
				((Structure) viewComposite).clearComponent(indices[i]);

				// Adjust the selection due to the clear.
				adjustSelection(indices[i] + 1, numBytes - 1);
				if (isSelected && numBytes > 1) {
					selection.addRange(indices[i] + 1, indices[i] + numBytes);
				}

				if (indices[i] > 0) {
					consumeByComponent(indices[i] - 1);
				}
			}
		});
		componentEdited();
	}

	@Override
	protected void deleteComponents(int[] rows) {
		if (isShowingUndefinedBytes()) {
			super.deleteComponents(rows);
			return;
		}
		int[] ordinals = convertRowsToOrdinals(rows);
		for (int i = ordinals.length - 1; i >= 0; i--) {
			viewComposite.delete(ordinals[i]);
		}
		notifyCompositeChanged();
	}

	private int[] convertRowsToOrdinals(int[] rows) {
		int[] ordinals = new int[rows.length];
		DataTypeComponent[] definedComponents = viewComposite.getDefinedComponents();
		for (int i = rows.length - 1; i >= 0; i--) {
			ordinals[i] = definedComponents[rows[i]].getOrdinal();
		}
		return ordinals;
	}

	@Override
	protected int convertRowToOrdinal(int rowIndex) {
		int numRowComponents = getNumComponents();
		if (rowIndex < 0 || rowIndex > numRowComponents) {
			return -1;
		}
		if (rowIndex == numRowComponents) {
			return viewComposite.getNumComponents();
		}
		if (isShowingUndefinedBytes()) {
			return rowIndex;
		}
		DataTypeComponent[] definedComponents = viewComposite.getDefinedComponents();
		return definedComponents[rowIndex].getOrdinal();
	}

	@Override
	public void duplicateMultiple(int index, int multiple, TaskMonitor monitor)
			throws UsrException {
		if (isEditingField()) {
			endFieldEditing();
		}

		DataTypeComponent originalComp = getComponent(index);
		if (originalComp == null) {
			throw new IllegalArgumentException("Invalid component index specified");
		}
		DataType dt = originalComp.getDataType();
		int len = dt.getLength();
		if (len < 0) {
			len = originalComp.getLength();
		}
		checkIsAllowableDataType(dt);

		int dtcLen = len;
		viewDTM.withTransaction("Duplicate Components", () -> {
			int startIndex = index + 1;
			if (dt != DataType.DEFAULT && isShowingUndefinedBytes() && !isAtEnd(index)) {
				int endIndex = startIndex + (dtcLen * multiple) - 1;
				if (startIndex < getNumComponents()) {
					deleteComponentRange(startIndex, endIndex, monitor);
				}
			}
			insertComponentMultiple(startIndex, dt, originalComp.getLength(), multiple, monitor);
		});

		// Adjust the selection since we added some components. Select last component added.
		// Ensure that last added component is selected to allow for repeated duplication
		setSelection(new int[] { index + multiple });

		componentEdited();
		lastNumDuplicates = multiple;
	}

	/**
	 *  Moves the components between the start index (inclusive) and the end
	 *  index (inclusive) to the new index (relative to the initial component set).
	 *
	 * @param startIndex row index of the starting component to move.
	 * @param endIndex row index of the ending component to move.
	 * @return true if components are moved.
	 */
	private boolean shiftComponentsUp(int startIndex, int endIndex) {
		int numComps = getNumComponents();
		if ((startIndex > endIndex) || startIndex <= 0 || startIndex >= numComps || endIndex <= 0 ||
			endIndex >= numComps) {
			return false;
		}
		int len = getLength();

		return viewDTM.withTransaction("Shift Up", () -> {
			DataTypeComponent comp = deleteComponentAndResidual(startIndex - 1);
			try {
				if (!isPackingEnabled() && comp.isBitFieldComponent()) {
					// insert residual undefined bytes before inserting non-packed bitfield
					int lenChange = len - getLength();
					insert(endIndex, DataType.DEFAULT, 1, lenChange, TaskMonitor.DUMMY);
				}
				insert(endIndex, comp.getDataType(), comp.getLength(), comp.getFieldName(),
					comp.getComment());
			}
			catch (CancelledException e) {
				// can't happen while using a dummy monitor
			}
			catch (InvalidDataTypeException e) {
				return false;
			}
			return true;
		});
	}

	/**
	 *  Moves the components between the start index (inclusive) and the end
	 *  index (exclusive) to the new index (relative to the initial component set).
	 *
	 * @param startIndex index of the starting component to move.
	 * @param endIndex index of the ending component to move.
	 * @return true if components are moved.
	 */
	private boolean shiftComponentsDown(int startIndex, int endIndex) {
		int numComponents = getNumComponents();
		if ((startIndex > endIndex) || startIndex < 0 || startIndex >= numComponents - 1 ||
			endIndex < 0 || endIndex >= numComponents - 1) {
			return false;
		}
		int len = getLength();

		return viewDTM.withTransaction("Shift Down", () -> {
			DataTypeComponent comp = deleteComponentAndResidual(endIndex + 1);
			try {
				if (!isPackingEnabled() && comp.isBitFieldComponent()) {
					// insert residual undefined bytes before inserting non-packed bitfield
					int lenChange = len - getLength();
					insert(startIndex, DataType.DEFAULT, 1, lenChange, TaskMonitor.DUMMY);
				}
				insert(startIndex, comp.getDataType(), comp.getLength(), comp.getFieldName(),
					comp.getComment());
			}
			catch (CancelledException e) {
				// can't happen while using a dummy monitor
			}
			catch (InvalidDataTypeException e) {
				return false;
			}
			return true;
		});
	}

	private DataTypeComponent deleteComponentAndResidual(int index) {

		DataTypeComponent comp = getComponent(index);
		deleteComponent(index);

		if (isPackingEnabled() || !comp.isBitFieldComponent() || index >= getNumComponents()) {
			return comp;
		}

		// Deleting a bitfield component does not remove consumed space.
		// This operation should remove any residual undefined components

		int startOffset = comp.getOffset();

		for (int i = index + comp.getLength() - 1; i >= index; --i) {
			DataTypeComponent dtc = getComponent(i);
			if (dtc != null && dtc.getDataType() == DataType.DEFAULT &&
				dtc.getOffset() >= startOffset) {
				deleteComponent(i);
			}
		}

		return comp;
	}

	@Override
	public boolean moveUp() throws NoSuchElementException {
		if (selection.getNumRanges() != 1) {
			return false;
		}
		if (isEditingField()) {
			endFieldEditing();
		}
		FieldRange range = selection.getFieldRange(0);
		int startRowIndex = range.getStart().getIndex().intValue();
		int endRowIndex = range.getEnd().getIndex().intValue() - 1;
		int numSelected = endRowIndex - startRowIndex + 1;
		boolean moved = false;
		int newIndex = startRowIndex - 1;
		moved = shiftComponentsUp(startRowIndex, endRowIndex);
		if (moved) {
			componentEdited();
			FieldSelection tmpFieldSelection = new FieldSelection();
			tmpFieldSelection.addRange(newIndex, newIndex + numSelected);
			setSelection(tmpFieldSelection);
		}
		return moved;
	}

	@Override
	public boolean moveDown() throws NoSuchElementException {
		if (selection.getNumRanges() != 1) {
			return false;
		}
		if (isEditingField()) {
			endFieldEditing();
		}
		FieldRange range = selection.getFieldRange(0);
		int startIndex = range.getStart().getIndex().intValue();
		int endIndex = range.getEnd().getIndex().intValue() - 1;
		int numSelected = endIndex - startIndex + 1;
		boolean moved = false;
		int newIndex = startIndex + 1;
		moved = shiftComponentsDown(startIndex, endIndex);
		if (moved) {
			componentEdited();
			FieldSelection tmpFieldSelection = new FieldSelection();
			tmpFieldSelection.addRange(newIndex, newIndex + numSelected);
			setSelection(tmpFieldSelection);
		}
		return moved;
	}

	// *************************************************************
	// Begin methods for determining if a type of edit action is allowed.
	// *************************************************************

	@Override
	public boolean isBitFieldAllowed() {
		return isSingleRowSelection();
	}

	/**
	 * Returns whether or not the selection
	 * is allowed to be changed into an array.
	 */
	@Override
	public boolean isArrayAllowed() {
		boolean allowed = false;
		if (!this.isContiguousSelection()) {
			return false;
		}
		// Get the range this index is in, if its in one.
		FieldRange range = selection.getFieldRange(0);

		DataTypeComponent comp = getComponent(range.getStart().getIndex().intValue());
		if (comp == null || comp.isBitFieldComponent()) {
			return false;
		}

		DataType dt = comp.getDataType();
		int dtLen = dt.getLength();
		// Can only create arrays from components that aren't broken.
		// (i.e. component and data type are same size.)
		if ((dtLen < 0) || (dtLen == comp.getLength())) {
			allowed = true;
		}
		return allowed;
	}

	@Override
	public boolean isClearAllowed() {
		return hasComponentSelection() && isShowingUndefinedBytes();
	}

	@Override
	public boolean isDeleteAllowed() {
		if (!hasSelection()) {
			return false;
		}
		int rowIndex = selection.getFieldRange(0).getStart().getIndex().intValue();
		return getComponent(rowIndex) != null;
	}

	@Override
	public boolean isDuplicateAllowed() {

		if (!isSingleRowSelection() || this.getNumSelectedComponentRows() != 1) {
			return false;
		}

		// set actions based on number of items selected
		int rowIndex = getRow();
		DataTypeComponent comp = getComponent(rowIndex);
		if (comp == null) {
			return false;
		}
		if (viewComposite.isPackingEnabled() || isAtEnd(rowIndex)) {
			return true;
		}
		DataType dt = comp.getDataType();
		if (dt.equals(DataType.DEFAULT)) {
			return true; // Insert an undefined and push everything down.
		}
		if (comp.isBitFieldComponent()) {
			return false; // unable to place non-packed bitfield in a reasonable fashion
		}

		// Get the size of the data type at this index and the number of
		// undefined bytes following it.
		int dtSize = dt.getLength();
		if (dtSize <= 0) {
			dtSize = comp.getLength();
		}
		if (dtSize <= getNumUndefinedBytesAfter(comp)) {
			return true;
		}
		return false;
	}

	@Override
	public boolean isUnpackageAllowed() {
		// set actions based on number of items selected
		boolean unpackageAllowed = false;
		if (this.getNumSelectedComponentRows() != 1) {
			return false;
		}

		int currentIndex = selection.getFieldRange(0).getStart().getIndex().intValue();
		// Get the range this index is in, if its in one.
		FieldRange range = getSelectedRangeContaining(currentIndex);
		boolean notInMultiLineSelection = true;
		if ((range != null) &&
			((range.getEnd().getIndex().intValue() - range.getStart().getIndex().intValue()) > 1)) {
			notInMultiLineSelection = false;
		}

		// set actions based on number of items selected
		if (notInMultiLineSelection && (currentIndex < getNumComponents())) {

			DataTypeComponent comp = getComponent(currentIndex);
			DataType dt = comp.getDataType();
			// Can only unpackage components that aren't broken.
			// (i.e. component and data type are same size.)
			if (comp.getLength() == dt.getLength()) {
				// Array or structure can be unpackaged.
				if (dt instanceof Array || (dt instanceof Structure)) {
					unpackageAllowed = true;
				}
			}
		}
		return unpackageAllowed;
	}

	/**
	 * Returns whether or not addition of the specified component is allowed
	 * at the specified index. the addition could be an insert or replace as
	 * determined by the state of the edit model.
	 *
	 * @param currentIndex index of the component in the structure.
	 * @param datatype the data type to be inserted.
	 */
	@Override
	public boolean isAddAllowed(int currentIndex, DataType datatype) {
		if (currentIndex < 0 || currentIndex > getRowCount()) {
			return false;
		}

		// Don't allow arrays to be dropped on pointers or arrays.
		if (datatype instanceof Array) {
			DataTypeComponent comp = getComponent(currentIndex);
			if (comp != null) {
				DataType compDt = comp.getDataType();
				if (compDt instanceof Array || compDt instanceof Pointer) {
					return false;
				}
			}
		}

		FieldRange currentRange = getSelectedRangeContaining(currentIndex);
		// if the index isn't in the selection or is in a range of only
		// one row then we want to handle it the same.
		boolean isOneComponent =
			(currentRange == null) || (currentRange.getStart().getIndex().intValue() +
				1 == currentRange.getEnd().getIndex().intValue());

		if (isOneComponent) {
			if (isPackingEnabled() || isAtEnd(currentIndex)) {
				return true; // allow replace of component when aligning.
			}

			// FreeForm editing mode (showing Undefined Bytes).
			// Only drop on undefined, pointer, or another type in same cycle group.
			DataTypeComponent comp = getComponent(currentIndex);
			if (comp != null) {
				DataType compDt = comp.getDataType();
				if (compDt instanceof Pointer ||
					DataTypeHelper.getBaseType(compDt) instanceof Pointer) {
					// Don't create undefined byte pointers.
					if (datatype.equals(DataType.DEFAULT)) {
						return false;
					}
					return true;
				}
				int numAvailable = comp.getLength() + getNumUndefinedBytesAfter(comp);
				return datatype.getLength() <= numAvailable;
			}
			return true;
		}
		int numComps = getNumComponents();
		int firstIndex = currentRange.getStart().getIndex().intValue();
		int lastIndex = currentRange.getEnd().getIndex().intValue() - 1;
		if ((firstIndex >= numComps) || (lastIndex >= numComps)) {
			return false;
		}
		DataTypeComponent startComp = getComponent(firstIndex);
		DataTypeComponent endComp = getComponent(lastIndex);
		int numAvailable = endComp.getOffset() + endComp.getLength() - startComp.getOffset();
		if (datatype.getLength() <= numAvailable) {
			return true;
		}
		return false;
	}

	/**
	 * Returns whether or not insertion of the specified component is allowed
	 * at the specified index.
	 *
	 * @param currentIndex index of the component in the structure.
	 * @param datatype the data type to be inserted.
	 */
	@Override
	public boolean isInsertAllowed(int currentIndex, DataType datatype) {
		if (currentIndex > getNumComponents()) {
			return false;
		}
		return true;
	}

	@Override
	public boolean isReplaceAllowed(int rowIndex, DataType dataType) {

		DataTypeComponent dtc = getComponent(rowIndex);
		if (dtc == null) {
			return false;
		}

		try {
			checkIsAllowableDataType(dataType);
		}
		catch (InvalidDataTypeException e) {
			return false;
		}

		if (isPackingEnabled() || isAtEnd(rowIndex)) {
			return true;
		}

		int undefSize = getNumUndefinedBytesAfter(dtc);
		if (undefSize < 0) {
			return true;
		}

		int numAvailable = dtc.getLength() + undefSize;
		return dataType.getLength() <= numAvailable;
	}

	// *************************************************************
	// End of methods for determining if a type of edit action is allowed.
	// *************************************************************

	/**
	 * Gets the maximum number of bytes available for a data type that is added at the indicated
	 * index. This can vary based on whether or not it is in a selection.
	 * <br>In unlocked mode, the size is unrestricted when no selection or single row selection.
	 * Multi-row selection always limits the size.
	 * <br>In locked mode, single row selection is limited to selected row plus undefined bytes
	 * following it that can be absorbed.
	 *
	 * @param rowIndex index of the row in the editor's composite data type table.
	 * @return the max length or -1 for no limit.
	 */
	@Override
	public int getMaxAddLength(int rowIndex) {
		if (rowIndex >= getNumComponents() - 1) {
			return Integer.MAX_VALUE;
		}
		if (isPackingEnabled() || isAtEnd(rowIndex)) {
			return Integer.MAX_VALUE;
		}
		DataTypeComponent comp = getComponent(rowIndex);
		FieldRange currentRange = getSelectedRangeContaining(rowIndex);
		// if the index isn't in the selection or is in a range of only
		// one row then we want to handle it the same.
		boolean isOneComponent =
			(currentRange == null) || (currentRange.getStart().getIndex().intValue() +
				1 == currentRange.getEnd().getIndex().intValue());

		if (isOneComponent) {
			return comp.getLength() + getNumUndefinedBytesAfter(comp);
		}
		return getNumBytesInRange(currentRange);
	}

	/**
	 * Gets the maximum number of bytes available for a new data type that
	 * will replace the current data type at the indicated index.
	 * If there isn't a component with the indicated index, the max length
	 * will be determined by the lock mode.
	 *
	 * @param currentIndex index of the component in the structure.
	 * @return the maximum number of bytes that can be replaced.
	 */
	@Override
	public int getMaxReplaceLength(int currentIndex) {

		if (currentIndex >= getNumComponents() - 1) {
			return Integer.MAX_VALUE;
		}
		if (isPackingEnabled() || isAtEnd(currentIndex)) {
			return Integer.MAX_VALUE;
		}

		// Can only replace with what fits unless at last component or empty last line.
		DataTypeComponent comp = getComponent(currentIndex);
		int numComponents = getNumComponents();
		if ((currentIndex >= (numComponents - 1)) && (currentIndex <= numComponents)) {
			return Integer.MAX_VALUE; // Last component or empty entry immediately after it.
		}
		if (comp == null) {
			return 0; // No such component. Not at valid edit index.
		}

		// Otherwise, get size of component and number of Undefined bytes after it.
		FieldRange currentRange = getSelectedRangeContaining(currentIndex);
		boolean isOneComponent =
			(currentRange == null) || (currentRange.getStart().getIndex().intValue() +
				1 == currentRange.getEnd().getIndex().intValue());

		if (isOneComponent) {
			return comp.getLength() + getNumUndefinedBytesAfter(comp);
		}
		return getNumBytesInRange(currentRange);
	}

	/**
	 * Returns the number of bytes that are included in the current selection
	 * range.
	 *
	 * @param range the range of indices for the component's whose sizes should
	 * be added together.
	 */
	@Override
	protected int getNumBytesInRange(FieldRange range) {
		int numBytesInRange = 0;
		if (range != null) {
			// Determine the number of bytes.
			// Get the size of the range.
			int startIndex = range.getStart().getIndex().intValue();
			int endIndex = range.getEnd().getIndex().intValue() - 1;
			DataTypeComponent startComp = getComponent(startIndex);
			DataTypeComponent endComp = getComponent(endIndex);
			numBytesInRange = endComp.getOffset() + endComp.getLength();
			numBytesInRange -= startComp.getOffset();
		}
		return numBytesInRange;
	}

	@Override
	protected DataTypeComponent insert(int rowIndex, DataType dataType, int length, String name,
			String comment) throws InvalidDataTypeException {
		checkIsAllowableDataType(dataType);
		try {
			return viewDTM.withTransaction("Insert Component", () -> {
				DataTypeComponent dtc;
				if (isPackingEnabled() || !(dataType instanceof BitFieldDataType)) {
					dtc = viewComposite.insert(rowIndex, dataType, length, name,
						comment);
				}
				else {
					BitFieldDataType bitfield = (BitFieldDataType) dataType;
					dtc = ((Structure) viewComposite).insertBitField(rowIndex, length,
						bitfield.getBitOffset(), bitfield.getBaseDataType(),
						bitfield.getDeclaredBitSize(), name, comment);
				}
				if (rowIndex <= currentEditRow) {
					currentEditRow++;
				}
				adjustSelection(rowIndex, 1);
				// Consume undefined bytes that may have been added, if needed.
				consumeByComponent(rowIndex - 1);

				return dtc;
			});
		}
		catch (IllegalArgumentException exc) {
			throw new InvalidDataTypeException(exc.getMessage());
		}
	}

	@Override
	protected void insert(int rowIndex, DataType dataType, int length, int numCopies,
			TaskMonitor monitor) throws InvalidDataTypeException, CancelledException {

		checkIsAllowableDataType(dataType);
		int componentOrdinal = convertRowToOrdinal(rowIndex);
		monitor.initialize(numCopies);
		try {
			viewDTM.withTransaction("Insert Multiple", () -> {
				for (int i = 0; i < numCopies; i++) {
					monitor.checkCancelled();
					monitor.setMessage("Inserting " + (i + 1) + " of " + numCopies);
					viewComposite.insert(componentOrdinal, dataType, length);
					monitor.incrementProgress(1);
				}

				if (rowIndex <= currentEditRow) {
					currentEditRow += numCopies;
				}
				adjustSelection(componentOrdinal, numCopies);
				// Consume undefined bytes that may have been added, if needed.
				consumeByComponent(componentOrdinal - numCopies);
			});
		}
		catch (IllegalArgumentException exc) {
			throw new InvalidDataTypeException(exc.getMessage());
		}
	}

	@Override
	protected DataTypeComponent replace(int rowIndex, DataType dataType, int length, String name,
			String comment) throws InvalidDataTypeException {
		checkIsAllowableDataType(dataType);
		try {
			DataTypeComponent dtc = null;
			boolean isSelected = selection.containsEntirely(BigInteger.valueOf(rowIndex));
			int diffLen = 0;
			int componentOrdinal = convertRowToOrdinal(rowIndex);

			// FreeForm editing mode (showing Undefined Bytes).
			if (!isPackingEnabled() && !isAtEnd(rowIndex)) {
				int origLen = getComponent(rowIndex).getLength();
				dtc = viewDTM.withTransaction("Replace Component", () -> {
					return ((Structure) viewComposite).replace(componentOrdinal, dataType, length,
						name, comment);
				});
				diffLen = origLen - dtc.getLength();
				int nextRowIndex = rowIndex + 1;
				if (diffLen < 0) {
					selection.removeRange(nextRowIndex, nextRowIndex - diffLen);
					adjustSelection(nextRowIndex, diffLen);
				}
				else if (diffLen > 0) {
					adjustSelection(nextRowIndex, diffLen);
					if (isSelected) {
						selection.addRange(nextRowIndex, nextRowIndex + diffLen);
					}
				}
				if (rowIndex < currentEditRow) {
					currentEditRow += diffLen;
				}
			}
			else {
				dtc = viewDTM.withTransaction("Replace Component", () -> {
					Structure struct = (Structure) viewComposite;
					DataTypeComponent comp = getComponent(rowIndex);
					if (!isPackingEnabled()) {
						// We are at end with packing disabled - grow structure if needed
						int avail = comp.getLength() + getNumUndefinedBytesAfter(comp);
						if (length > avail) {
							struct.growStructure(length - avail);
						}
					}
					return ((Structure) viewComposite).replace(componentOrdinal, dataType, length,
						name, comment);
				});
			}
			return dtc;
		}
		catch (IllegalArgumentException exc) {
			// NOTE: Use of exception may cause transaction rollback
			throw new InvalidDataTypeException(exc.getMessage());
		}
	}

	@Override
	protected boolean replaceRange(int startRowIndex, int endRowIndex, DataType datatype,
			int length, TaskMonitor monitor)
			throws InvalidDataTypeException, InsufficientBytesException, CancelledException {

		if (startRowIndex > endRowIndex) {
			return false;
		}

		// Get the size of the range.
		DataTypeComponent startComp = getComponent(startRowIndex);
		DataTypeComponent endComp = getComponent(endRowIndex);
		int numBytesInRange = endComp.getOffset() + endComp.getLength();
		numBytesInRange -= startComp.getOffset();

		if (length > numBytesInRange) {
			throw new InsufficientBytesException(
				"\"" + datatype.getDisplayName() + "\" does not fit in selection.");
		}

		// Determine how many copies of new data type to add.
		int numComps = numBytesInRange / length;

		// Get the field name and comment before removing.
		String fieldName = startComp.getFieldName();
		String comment = startComp.getComment();

		FieldSelection overlap = new FieldSelection();
		overlap.addRange(startRowIndex, endRowIndex + 1);
		overlap.intersect(selection);
		boolean replacedSelected = (overlap.getNumRanges() > 0);

		int txId = viewDTM.startTransaction("Replace Multiple");
		try {
			// Remove the selected components.
			deleteComponentRange(startRowIndex, endRowIndex, monitor);

			int beginUndefs = startRowIndex + numComps;
			// Create the new components.
			insertMultiple(startRowIndex, datatype, length, numComps, monitor);
			int indexAfterMultiple = startRowIndex + numComps;
			if (replacedSelected) {
				selection.addRange(startRowIndex, indexAfterMultiple);
				fixSelection();
			}

			DataTypeComponent comp = getComponent(startRowIndex);
			// Set the field name and comment the same as before
			try {
				comp.setFieldName(fieldName);
			}
			catch (DuplicateNameException exc) {
				Msg.showError(this, null, null, null);
			}
			comp.setComment(comment);

			// Create any needed undefined data types.
			int remainingLength = numBytesInRange - (numComps * length);
			if (remainingLength > 0 && isShowingUndefinedBytes()) {
				try {
					insertComponentMultiple(beginUndefs, DataType.DEFAULT,
						DataType.DEFAULT.getLength(), remainingLength, monitor);
					if (replacedSelected) {
						selection.addRange(indexAfterMultiple,
							indexAfterMultiple + remainingLength);
					}
				}
				catch (InvalidDataTypeException idte) {
					Msg.showError(this, null, "Structure Editor Error", idte.getMessage());
				}
			}
			else if (remainingLength < 0) {
				return false;
			}
			return true;
		}
		finally {
			viewDTM.endTransaction(txId, true);
		}
	}

	@Override
	protected void replaceOriginalComponents() {
		Structure dt = (Structure) getOriginalComposite();
		if (dt != null) {
			dt.replaceWith(viewComposite);
		}
		else {
			throw new RuntimeException("ERROR: Couldn't replace structure components in " +
				getOriginalDataTypeName() + ".");
		}
	}

	@Override
	void removeDtFromComponents(Composite comp) {
		DataType newDt = viewDTM.getDataType(comp.getDataTypePath());
		if (newDt == null) {
			return;
		}
		boolean clearedComponents = viewDTM.withTransaction("Remove Components", () -> {
			boolean cleared = false;
			int num = getNumComponents();
			for (int i = num - 1; i >= 0; i--) {
				DataTypeComponent dtc = getComponent(i);
				DataType dt = dtc.getDataType();
				if (dt instanceof Composite) {
					Composite dtcComp = (Composite) dt;
					if (dtcComp.isPartOf(newDt)) {
						clearComponents(new int[] { i });
						cleared = true;
					}
				}
			}
			return cleared;
		});
		if (clearedComponents) {
			setStatus("Components containing " + comp.getDisplayName() + " were cleared.", true);
		}
	}

	@Override
	public boolean isShowingUndefinedBytes() {
		return !viewComposite.isPackingEnabled();
	}

	void createInternalStructure() throws UsrException {

		if (selection.getNumRanges() != 1) {
			throw new UsrException("Can only create structure on a contiguous selection.");
		}

		FieldRange fieldRange = selection.getFieldRange(0);
		int minRow = fieldRange.getStart().getIndex().intValue();
		int maxRow = fieldRange.getEnd().getIndex().intValue();
		int selectedRowCount = maxRow - minRow;
		if (selectedRowCount == 1) {
			// Popup are you sure dialog.
			int choice = OptionDialog.showYesNoDialog(provider.getComponent(),
				"Create Structure From Selected Components",
				"You only have a single component selected.\nAre you sure you want to create a structure from the selection?");
			if (choice == OptionDialog.NO_OPTION) {
				// If user chooses no, then bail out.
				return;
			}
		}

		if (isEditingField()) {
			endFieldEditing();
		}

		DataTypeManager originalDtm = getOriginalDataTypeManager();
		CategoryPath originalCategoryPath = getOriginalCategoryPath();
		String uniqueName = getUniqueDataTypeName(originalCategoryPath, "struct");

		String specifiedName =
			showNameDialog(uniqueName, originalCategoryPath, viewComposite.getName(), originalDtm);
		if (specifiedName == null) {
			return;
		}

		TaskLauncher.launchModal("Create Structure", monitor -> {
			try {
				doCreateInternalStructure(originalDtm, originalCategoryPath, specifiedName,
					monitor);
			}
			catch (UsrException e) {
				setStatus(e.getMessage(), true);
			}
		});
	}

	/**
	 * Get a unique datatype name.  Method based on the logic used by 
	 * {@link DataTypeManager#getUniqueName(CategoryPath, String)} but 
	 * checks both the original and view DTMs for uniqueness.
	 * @param path category path
	 * @param baseName datatype name
	 * @return unique datatype name
	 */
	private String getUniqueDataTypeName(CategoryPath path, String baseName) {
		int pos = baseName.lastIndexOf('_');
		int oneUpNumber = 0;
		String name = baseName;
		if (pos > 0) {
			String numString = baseName.substring(pos + 1);
			try {
				oneUpNumber = Integer.parseInt(numString);
				name = baseName;
				baseName = baseName.substring(0, pos);
			}
			catch (NumberFormatException e) {
				// the number will get updated below
			}
		}
		DataTypeManager originalDtm = getOriginalDataTypeManager();
		// Pick a name not used within either original or view DTM
		while (originalDtm.getDataType(path, name) != null ||
			viewDTM.getDataType(path, name) != null) {
			++oneUpNumber;
			name = baseName + "_" + oneUpNumber;
		}
		return name;
	}

	private void doCreateInternalStructure(DataTypeManager dtm, CategoryPath categoryPath,
			String name, TaskMonitor monitor) throws InvalidDataTypeException, UsrException {

		int length = 0;
		StructureDataType structureDataType =
			new StructureDataType(categoryPath, name, length, dtm);

		// adopt pack setting from current structure
		structureDataType.setPackingEnabled(isPackingEnabled());
		if (getPackingType() == PackingType.EXPLICIT) {
			structureDataType.setExplicitPackingValue(getExplicitPackingValue());
		}

		FieldRange fieldRange = selection.getFieldRange(0);
		int minRow = fieldRange.getStart().getIndex().intValue();
		int maxRow = fieldRange.getEnd().getIndex().intValue();

		// Get data type components to make into structure.
		DataTypeComponent firstDtc = null;
		DataTypeComponent lastDtc = null;
		for (int rowIndex = minRow; rowIndex < maxRow; rowIndex++) {
			DataTypeComponent component = getComponent(rowIndex);
			if (rowIndex == minRow) {
				firstDtc = component;
			}
			if (component == null) {
				lastDtc = component;
				continue;
			}

			DataType dt = component.getDataType();
			int compLength = component.getLength();
			length += compLength;

			if (!structureDataType.isPackingEnabled() && component.isBitFieldComponent()) {
				BitFieldDataType bitfield = (BitFieldDataType) dt;
				structureDataType.insertBitFieldAt(component.getOffset() - firstDtc.getOffset(),
					compLength, bitfield.getBitOffset(), bitfield.getBaseDataType(),
					bitfield.getDeclaredBitSize(), component.getFieldName(),
					component.getComment());
			}
			else {
				structureDataType.add(dt, compLength, component.getFieldName(),
					component.getComment());
			}

			lastDtc = component;
		}

		DataType addedDataType = createDataTypeInOriginalDTM(structureDataType);

		int txId = viewDTM.startTransaction("Replace w/Structure");
		try {
			if (viewComposite.isPackingEnabled()) {
				deleteSelectedComponents();
				insert(minRow, addedDataType, addedDataType.getLength());
			}
			else {
				int adjustmentBytes = 0;
				if (firstDtc != null && firstDtc.isBitFieldComponent() && minRow > 0) {
					DataTypeComponent dtc = getComponent(minRow - 1);
					if (dtc.getEndOffset() == firstDtc.getOffset()) {
						++adjustmentBytes;
					}
				}
				if (lastDtc != null && lastDtc.isBitFieldComponent() &&
					maxRow < getNumComponents()) {
					DataTypeComponent dtc = getComponent(maxRow);
					if (dtc.getOffset() == lastDtc.getEndOffset()) {
						++adjustmentBytes;
					}
				}
				clearSelectedComponents();
				insertMultiple(minRow, DataType.DEFAULT, 1, adjustmentBytes, monitor);
				replace(minRow, addedDataType, addedDataType.getLength());
			}
		}
		finally {
			viewDTM.endTransaction(txId, true);
		}
	}

	private String showNameDialog(final String defaultName, final CategoryPath catPath,
			final String parentStructureName, final DataTypeManager applyDTM) {
		InputDialogListener listener = dialog -> {
			String name = dialog.getValue();
			if ((name == null) || (name.length() == 0)) {
				dialog.setStatusText("A name must be specified.");
				return false;
			}
			if (name.equals(parentStructureName)) {
				dialog.setStatusText("The name cannot match the external structure name.");
				return false;
			}

			DataTypeManager originalDtm = getOriginalDataTypeManager();
			DataType conflictingDt = originalDtm.getDataType(getOriginalCategoryPath(), name);
			if (conflictingDt != null) {
				dialog.setStatusText("A data type named \"" + name + "\" already exists.");
				return false;
			}
			return true;
		};

		String title = "Specify the Structure's Name";
		InputDialog nameStructureDialog = new InputDialog(title,
			new String[] { "New Structure's Name: " }, new String[] { defaultName }, listener);

		provider.getPlugin().getTool().showDialog(nameStructureDialog);

		if (nameStructureDialog.isCanceled()) {
			return null;
		}
		return nameStructureDialog.getValue();

	}

	private DataType createDataTypeInOriginalDTM(StructureDataType structureDataType) {
		boolean commit = false;
		int transactionID =
			originalDTM.startTransaction("Create structure " + structureDataType.getName());
		try {
			DataType addedDataType =
				originalDTM.addDataType(structureDataType, DataTypeConflictHandler.DEFAULT_HANDLER);
			commit = true;
			return addedDataType;
		}
		finally {
			originalDTM.endTransaction(transactionID, commit);
		}
	}

	/**
	 * Unpackage the selected component in the structure or array. This means replace the structure
	 * with the data types for its component parts. For an array replace the array with the data type
	 * for each array element.
	 * If the component isn't a structure or union then returns false.
	 * @param rowIndex the row
	 * @param monitor the task monitor
	 * @throws UsrException if the component can't be unpackaged.
	 */
	public void unpackage(int rowIndex, TaskMonitor monitor) throws UsrException {
		int componentOrdinal = convertRowToOrdinal(rowIndex);
		DataTypeComponent currentComp = viewComposite.getComponent(componentOrdinal);
		if (currentComp == null) {
			throw new UsrException("Can only unpackage an array or structure.");
		}
		DataType currentDataType = currentComp.getDataType();
		if (!((currentDataType instanceof Array) || (currentDataType instanceof Structure))) {
			throw new UsrException("Can only unpackage an array or structure.");
		}
		if (isEditingField()) {
			endFieldEditing();
		}

		viewDTM.withTransaction("Unpack Component", () -> {
			Structure viewStruct = (Structure) viewComposite;

			// Get the field name and comment before removing.
			String fieldName = currentComp.getFieldName();
			String comment = currentComp.getComment();
			int numComps = 0;
			// This component is an array so unpackage it.
			if (currentDataType instanceof Array) {
				Array array = (Array) currentDataType;
				int elementLen = array.getElementLength();
				numComps = array.getNumElements();
				// Remove the array.
				delete(componentOrdinal);
				if (numComps > 0) {
					// Add the array's elements
					try {
						DataType dt = array.getDataType();
						insertMultiple(rowIndex, dt, elementLen, numComps, monitor);
					}
					catch (InvalidDataTypeException ie) {
						// Do nothing.
					}
					catch (OutOfMemoryError memExc) {
						throw memExc; // rethrow the exception.
					}
				}
			}
			// This component is a structure so unpackage it.
			else if (currentDataType instanceof Structure) {
				Structure struct = (Structure) currentDataType;
				numComps = struct.getNumComponents();
				if (numComps > 0) {
					// Remove the structure.
					int currentOffset = currentComp.getOffset();
					deleteComponent(rowIndex);

					// Add the structure's elements
					for (int i = 0; i < numComps; i++) {
						DataTypeComponent dtc = struct.getComponent(i);
						DataType dt = dtc.getDataType();
						int compLength = dtc.getLength();
						if (!isPackingEnabled()) {
							if (dtc.isBitFieldComponent()) {
								BitFieldDataType bitfield = (BitFieldDataType) dt;
								viewStruct.insertBitFieldAt(currentOffset + dtc.getOffset(),
									compLength, bitfield.getBitOffset(), bitfield.getBaseDataType(),
									bitfield.getDeclaredBitSize(), dtc.getFieldName(),
									dtc.getComment());
							}
							else {
								viewStruct.insertAtOffset(currentOffset + dtc.getOffset(), dt,
									compLength, dtc.getFieldName(), dtc.getComment());
							}
						}
						else {
							insert(rowIndex + i, dt, compLength, dtc.getFieldName(),
								dtc.getComment());
						}
					}
				}
			}
			selection.clear();
			selection.addRange(rowIndex, rowIndex + numComps);

			DataTypeComponent comp = getComponent(rowIndex);
			// Set the field name and comment the same as before
			try {
				if (comp.getFieldName() == null) {
					comp.setFieldName(fieldName);
				}
			}
			catch (DuplicateNameException exc) {
				Msg.showError(this, null, null, null);
			}
			comp.setComment(comment);
		});
		fixSelection();
		componentEdited();
		selectionChanged();
	}
}
