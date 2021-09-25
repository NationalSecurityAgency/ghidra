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
import java.util.NoSuchElementException;

import docking.widgets.fieldpanel.support.FieldRange;
import docking.widgets.fieldpanel.support.FieldSelection;

/**
 * Data union editor model for maintaining information about the edits being
 * performed. Updates the union to indicate component changes to
 * the data union. Maintains information about the editor fields (columns)
 * for a component. Maintains information about the state of the editor:
 * lock/unlock mode, type of composite (structure/union) , and
 * whether or not the union has been modified.
 * It also notifies any registered CompositeEditorModelListener listeners when
 * the union is changed.
 * <P>This model provides methods for editing the union and managing how
 * the changes occur depending on whether or not components are selected and
 * whether editing in locked or unlocked mode.
 * Currently unions are only designed to work in unlocked mode.
 * When edit actions occur and there is a selection, the listener's are notified
 * of the new selection via the listener's overrideSelection method.
 */

import ghidra.program.model.data.*;
import ghidra.program.model.lang.InsufficientBytesException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.UsrException;
import ghidra.util.task.TaskMonitor;

class UnionEditorModel extends CompEditorModel {

	private static final long serialVersionUID = 1L;
	private static final int LENGTH = 0;
	private static final int MNEMONIC = 1;
	private static final int DATATYPE = 2;
	private static final int FIELDNAME = 3;
	private static final int COMMENT = 4;

	UnionEditorModel(UnionEditorProvider provider, boolean showInHex) {
		super(provider);
		headers = new String[] { "Length", "Mnemonic", "DataType", "Name", "Comment" };
		columnWidths = new int[] { 75, 100, 100, 100, 150 };
		columnOffsets = new int[headers.length];
		adjustOffsets();
		this.showHexNumbers = showInHex;

	}

	@Override
	public int getOffsetColumn() {
		return -1;
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
	 *  returns whether or not a particular component row and field in this
	 *  structure is editable.
	 *  <P>Warning: There shouldn't be a selection when this is called.
	 *
	 * @param rowIndex the row index in the component table.
	 * @param columnIndex the index for the field of the component.
	 */
	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		if (getNumSelectedRows() != 1) {
			return false;
		}
		int numComponents = getNumComponents();
		if ((rowIndex < 0) || (rowIndex > numComponents)) {
			return false;
		}
		// There shouldn't be a selection when this is called.
		switch (columnIndex) {
			case DATATYPE:
				if ((rowIndex >= 0) && (rowIndex <= numComponents)) {
					return true;
				}
				return false;
			case FIELDNAME:
			case COMMENT:
				if (rowIndex >= numComponents) {
					return false;
				}
				DataType dt = getComponent(rowIndex).getDataType();
				if (dt == DataType.DEFAULT) {
					return false;
				}
				return true;
			default:
				return false; // User can't edit any other fields.
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
				case DATATYPE:
					setComponentDataType(rowIndex, value);
					break;
				case FIELDNAME:
					setComponentName(rowIndex, ((String) value).trim());
					break;
				case COMMENT:
					setComponentComment(rowIndex, (String) value);
					break;
				default:
					return false;
			}
			return true;
		}
		catch (UsrException e) {
			setStatus(e.getMessage());
			return false;
		}
		finally {
			applyingFieldEdit = false;
		}
	}

	@Override
	public void clearComponent(int rowIndex) {
		// clearing not supported
	}

	/**
	 * Clear the selected components
	 *
	 * @throws UsrException if clearing isn't allowed
	 */
	@Override
	public void clearSelectedComponents() throws UsrException {
		throw new UsrException("Clearing is not allowed.");
	}

	@Override
	protected void createArray(int numElements)
			throws InvalidDataTypeException, DataTypeConflictException, UsrException {
		if (getNumSelectedComponentRows() != 1) {
			throw new UsrException("Select an individual component to create an array.");
		}
		super.createArray(numElements);
	}

	public boolean isLockable() {
		return false;
	}

//==================================================================================================
// Begin methods for determining if a type of edit action is allowed.
//==================================================================================================	

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
		if (!isSingleRowSelection()) {
			return false;
		}
		FieldRange range = selection.getFieldRange(0);
		DataTypeComponent comp = getComponent(range.getStart().getIndex().intValue());
		return (comp != null && !comp.isBitFieldComponent());
	}

	/**
	 * Returns whether or not clearing the component at the specified index is allowed
	 */
	@Override
	public boolean isClearAllowed() {
		return false;
	}

	/**
	 * Returns whether or not delete of the component at the selected index is allowed
	 */
	@Override
	public boolean isDeleteAllowed() {
		return (getNumSelectedComponentRows() != 0);
	}

	/**
	 * Returns whether or not the component at the selected index is allowed to be duplicated
	 */
	@Override
	public boolean isDuplicateAllowed() {
		return (this.getNumSelectedComponentRows() == 1);
	}

	/**
	 * Returns whether or not addition of the specified component is allowed
	 * at the specified index. the addition could be an insert or replace as
	 * determined by the state of the edit model.
	 *
	 * @param rowIndex index of the row in the union table.
	 * @param datatype the data type to be inserted.
	 */
	@Override
	public boolean isAddAllowed(int rowIndex, DataType datatype) {
		if (datatype.equals(DataType.DEFAULT)) {
			return false;
		}
		// Don't allow arrays to be dropped on pointers or arrays.
		if (datatype instanceof Array) {
			DataTypeComponent comp = getComponent(rowIndex);
			if (comp != null) {
				DataType compDt = comp.getDataType();
				if (compDt instanceof Array || compDt instanceof Pointer) {
					return false;
				}
			}
		}

		return true;
	}

	/**
	 * Returns whether or not insertion of the specified component is allowed
	 * at the specified index.
	 *
	 * @param rowIndex index of the row in the union table.
	 * @param datatype the data type to be inserted.
	 */
	@Override
	public boolean isInsertAllowed(int rowIndex, DataType datatype) {
		if (datatype.equals(DataType.DEFAULT)) {
			return false;
		}
		return rowIndex <= viewComposite.getNumComponents();
	}

	@Override
	public boolean isReplaceAllowed(int currentIndex, DataType dataType) {
		try {
			if (currentIndex < 0 || currentIndex > getNumComponents()) {
				return false;
			}
			checkIsAllowableDataType(dataType);
		}
		catch (InvalidDataTypeException e) {
			return false;
		}
		return true;
	}

//==================================================================================================
// End of methods for determining if a type of edit action is allowed.
//==================================================================================================	

	/**
	 * Gets the maximum number of bytes available for a data type that is added at the indicated
	 * index.
	 *
	 * @param index index of the component in the union data type.
	 * @return no limit on union elements.
	 */
	@Override
	public int getMaxAddLength(int index) {
		return Integer.MAX_VALUE;
	}

	/**
	 * Gets the maximum number of bytes available for a new data type that 
	 * will replace the current data type at the indicated index.
	 * If there isn't a component with the indicated index, the max length 
	 * will be determined by the lock mode.
	 * Note: This method doesn't care whether there is a selection or not.
	 *
	 * @param currentIndex index of the component in the union.
	 * @return the maximum number of bytes that can be replaced 
	 */
	@Override
	public int getMaxReplaceLength(int currentIndex) {
		return Integer.MAX_VALUE;
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
			for (int i =
				range.getStart().getIndex().intValue(); i < range.getEnd().getIndex().intValue(); i++) {
				DataTypeComponent comp = getComponent(i);
				numBytesInRange = Math.max(numBytesInRange, comp.getLength());
			}
		}
		return numBytesInRange;
	}

	/**
	 *  Insert the named data type before the specified index.
	 *
	 * @param rowIndex index of the row (component).
	 *
	 * @throws InvalidDataTypeException if the union being edited is part
	 *         of the data type being inserted or if inserting isn't allowed.
	 * @throws DataTypeConflictException if creating the data type or one of
	 *         its sub-parts conflicted with an existing data type.
	 */
	@Override
	public DataTypeComponent insert(int rowIndex, DataType dt, int dtLength) throws UsrException {
		if (dt.equals(DataType.DEFAULT)) {
			throw new InvalidDataTypeException(
				"Inserting undefined bytes is not allowed in a union.");
		}

		return super.insert(rowIndex, dt, dtLength);
	}

	@Override
	public DataTypeComponent insert(int rowIndex, DataType dataType, int length, String name,
			String comment) throws InvalidDataTypeException {
		checkIsAllowableDataType(dataType);
		try {
			DataTypeComponent dtc =
				((Union) viewComposite).insert(rowIndex, dataType, length, name, comment);
			if (rowIndex <= row) {
				row++;
			}
			adjustSelection(rowIndex, 1);
			notifyCompositeChanged();
			return dtc;
		}
		catch (IllegalArgumentException exc) {
			throw new InvalidDataTypeException(exc.getMessage());
		}
	}

	@Override
	public void insert(int rowIndex, DataType dataType, int length, int numCopies,
			TaskMonitor monitor) throws InvalidDataTypeException, CancelledException {

		monitor.initialize(numCopies);
		for (int i = 0; i < numCopies; i++) {
			monitor.checkCanceled();
			insert(rowIndex + i, dataType, length, null, null);
			monitor.incrementProgress(1);
		}
	}

	@Override
	public DataTypeComponent replace(int rowIndex, DataType dataType, int length, String name,
			String comment) throws InvalidDataTypeException {
		checkIsAllowableDataType(dataType);
		try {
			boolean isSelected = selection.containsEntirely(BigInteger.valueOf(rowIndex));
			((Union) viewComposite).delete(rowIndex);
			DataTypeComponent dtc =
				((Union) viewComposite).insert(rowIndex, dataType, length, name, comment);
			if (isSelected) {
				selection.addRange(rowIndex, rowIndex + 1);
				fixSelection();
			}
			componentEdited();
			return dtc;
		}
		catch (IllegalArgumentException exc) {
			throw new InvalidDataTypeException(exc.getMessage());
		}
	}

	@Override
	protected boolean replaceRange(int startRowIndex, int endRowIndex, DataType datatype,
			int length, TaskMonitor monitor)
			throws InvalidDataTypeException, InsufficientBytesException, CancelledException {

		if (length <= 0) {
			throw new InvalidDataTypeException(
				"Can not replace a range with a " + length + " length data type.");
		}

		// Verify that we aren't adding this structure or anything that it is
		// part of to this editable structure.
		if (datatype.equals(viewComposite)) {
			String msg = datatype.getDisplayName() + " can't contain itself.";
			throw new InvalidDataTypeException(msg);
		}
		else if ((datatype instanceof Composite) &&
			(((Composite) datatype).isPartOf(viewComposite))) {
			String msg = "Can't replace with " + datatype.getDisplayName() + " since it has " +
				viewComposite.getDisplayName() + " within it.";
			throw new InvalidDataTypeException(msg);
		}

		if (startRowIndex > endRowIndex) {
			throw new IllegalArgumentException("startIndex of " + startRowIndex +
				" is greater than endIndex of " + endRowIndex + ".");
		}

		FieldSelection overlap = new FieldSelection();
		overlap.addRange(startRowIndex, endRowIndex + 1);
		overlap.intersect(selection);

		// Union just replaces entire selection range with single instance of new component.
		deleteComponentRange(startRowIndex, endRowIndex, monitor);

		boolean replacedSelected = (overlap.getNumRanges() > 0);
		insert(startRowIndex, datatype, length, null, null);
		if (replacedSelected) {
			selection.addRange(startRowIndex, startRowIndex + 1);
			fixSelection();
		}
		return true;
	}

	@Override
	public void replaceOriginalComponents() {
		((Union) getOriginalComposite()).replaceWith(viewComposite);
	}

	@Override
	public void clearComponents(int[] rows) throws UsrException {
		throw new UsrException("Can't clear components in a union.");
	}

	@Override
	void removeDtFromComponents(Composite comp) {
		DataType newDt = viewDTM.getDataType(comp.getDataTypePath());
		if (newDt == null) {
			return;
		}
		int num = getNumComponents();
		for (int i = num - 1; i >= 0; i--) {
			DataTypeComponent dtc = getComponent(i);
			DataType dt = dtc.getDataType();
			if (dt instanceof Composite) {
				Composite dtcComp = (Composite) dt;
				if (dtcComp.isPartOf(newDt)) {
					deleteComponent(i);
					String msg =
						"Components containing " + comp.getDisplayName() + " were removed.";
					setStatus(msg, true);
				}
			}
		}
	}

	/**
	 * Returns the number of undefined bytes that are available in the structure
	 * beginning at the specified row index.
	 *
	 * @param rowIndex the index of the row
	 */
	@Override
	protected int getNumUndefinedBytesAt(int rowIndex) {
		return 0;
	}

	/**
	 * ?????
	 *
	 * @param rowIndex the index of the row
	 */
	@Override
	protected boolean isAtEnd(int rowIndex) {
		return false;
	}

	/**
	 * Cause the component at the specified index to consume undefined bytes
	 * that follow it.
	 * Note: this method adjusts the selection.
	 * @return the number of Undefined bytes consumed.
	 */
	@Override
	protected int consumeByComponent(int rowIndex) {
		return 0;
	}

	/**
	 *  Consumes the number of undefined bytes requested if they are available.
	 *
	 * @param rowIndex index of the row (component).
	 * @param numDesired the number of Undefined bytes desired.
	 * @return the number of components removed from the structure when the
	 * bytes were consumed.
	 * @throws java.util.NoSuchElementException if the index is invalid.
	 * @throws InvalidDataTypeException if there aren't enough bytes.
	 */
	@Override
	protected int consumeUndefinedBytes(int rowIndex, int numDesired)
			throws NoSuchElementException, InvalidDataTypeException {
		return 0;
	}

	@Override
	public boolean isShowingUndefinedBytes() {
		return false;
	}

}
