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

import java.util.*;

import docking.widgets.OptionDialog;
import docking.widgets.fieldpanel.support.*;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Composite.AlignmentType;
import ghidra.program.model.lang.InsufficientBytesException;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.*;

public abstract class CompEditorModel extends CompositeEditorModel {

	/**
	 * Creates a model for editing a composite data type.
	 * @param provider the provider that is using this model for editing.
	 */
	CompEditorModel(CompositeEditorProvider provider) {
		super(provider);
	}

	@Override
	public boolean hasChanges() {
		DataTypeManager originalDTM = getOriginalDataTypeManager();
		if ((originalDTM != null) && !originalDTM.contains(originalComposite)) {
			return true;
		}
		return super.hasChanges();
	}

	/**
	 * Sets the data type that is being edited and the category where it will get saved.
	 * @param dataType the composite data type being edited.
	 */
	@Override
	public void load(Composite dataType) {
		super.load(dataType, true);
		fixSelection();
		selectionChanged();
	}

	/**
	 *  Returns the current dataType name (Structure or Union) as a string.
	 */
	@Override
	protected String getTypeName() {
		if (viewComposite instanceof Structure) {
			return "Structure";
		}
		else if (viewComposite instanceof Union) {
			return "Union";
		}
		return super.getTypeName();
	}

	/**
	 * Apply the changes for the current edited composite back to the
	 * original composite.
	 *
	 * @return true if apply succeeds
	 * @throws InvalidDataTypeException if this structure has a component that it is part of.
	 */
	@Override
	public boolean apply() throws InvalidDataTypeException {

		// commit changes for any fields under edit 
		if (isEditingField()) {
			endFieldEditing();
		}

		FieldSelection saveSelection = new FieldSelection(selection);
		Composite originalDt = getOriginalComposite();
		DataTypeManager originalDTM = getOriginalDataTypeManager();
		if (originalDt == null || originalDTM == null) {
			throw new IllegalStateException(
				"Can't apply edits without a data type or data type manager.");
		}
		int transactionID = originalDTM.startTransaction("Edit " + getCompositeName());
		try {
			if (originalDTM.contains(originalDt)) {

				// Update the original structure.
				String origName = originalDt.getName();
				String editName = getCompositeName();
				if (!origName.equals(editName)) {
					try {
						originalDt.setName(editName);
					}
					catch (InvalidNameException e) {
						String msg =
							"Apply failed. The data type name \"" + editName + "\" is not valid.";
						throw new InvalidDataTypeException(msg);
					}
					catch (DuplicateNameException e) {
						String msg =
							"Apply failed. A data type named \"" + editName + "\" already exists.";
						throw new InvalidDataTypeException(msg);
					}
				}
				originalDt.setDescription(getDescription());
				replaceOriginalComponents();
				load(originalDt, true);
			}
			else {
				Composite dt = (Composite) originalDTM.resolve(viewComposite, null);
				load(dt, true);
			}
			return true;
		}
		finally {
//			selection = saveSelection;
			setSelection(saveSelection);
			originalDTM.endTransaction(transactionID, true);
		}
	}

	// **********************************************************************
	// * OVERRIDDEN METHODS FOR THE SELECTION
	// **********************************************************************
	/**
	 *  Returns true if the GUI has the blank last line selected.
	 */
	boolean isBlankLastLineSelected() {
		return selection.contains(new FieldLocation(getNumComponents(), 0, 0, 0));
	}

	/**
	 * Returns the number of bytes that are included in the current selection
	 * range.
	 *
	 * @param range the range of indices for the component's whose sizes should
	 * be added together.
	 */
	protected abstract int getNumBytesInRange(FieldRange range);

	/**
	 *  Saves the current selection in the components viewing area.
	 *
	 * @param rows the indexes for the selected rows.
	 */
	@Override
	public void setSelection(int[] rows) {
		if (updatingSelection) {
			return;
		}
		FieldSelection tmpSelection = new FieldSelection();
		// allow any single row to be selected
		if (rows.length == 1) {
			tmpSelection.addRange(rows[0], rows[0] + 1);
		}
		else {
			// restrict multi-selection to defined components only
			int numComponents = getNumComponents();
			for (int i = 0; i < rows.length; i++) {
				// Only add valid component rows (i.e. don't include blank last line)
				if (rows[i] < numComponents) {
					tmpSelection.addRange(rows[i], rows[i] + 1);
				}
			}
		}
		if (tmpSelection.getNumRanges() == 0) {
			// select empty edit row by default
			int numComponents = getNumComponents();
			tmpSelection.addRange(numComponents, numComponents + 1);
		}
		if (this.selection.equals(tmpSelection)) {
			selectionChanged();
			return;
		}
		endFieldEditing();
		this.selection = tmpSelection;
		adjustCurrentRow();
		selectionChanged();
	}

	/**
	 * Sets the model's current selection to the indicated selection.
	 * If the selection is empty, it gets adjusted to the empty last line.
	 * @param selection the new selection
	 */
	@Override
	public void setSelection(FieldSelection selection) {
		if (updatingSelection) {
			return;
		}
		if (this.selection.equals(selection)) {
			return;
		}
		endFieldEditing();
		this.selection.clear();
		int numRanges = selection.getNumRanges();
		for (int i = 0; i < numRanges; i++) {
			FieldRange range = selection.getFieldRange(i);
			this.selection.addRange(range.getStart().getIndex().intValue(),
				range.getEnd().getIndex().intValue());
		}
		fixSelection();
		adjustCurrentRow();
		selectionChanged();
	}

	/**
	 * This adjusts the selection so the blank last line cannot be selected
	 * if any components are selected.
	 * In no components are selected, this will select the blank last line.
	 * @return true if the selection was changed.
	 */
	boolean fixSelection() {
		int numComps = getNumComponents();

		// Make sure we don't have a selection with rows outside the table.
		// This can happen due to switching between aligned and unaligned.
		FieldSelection allRows = new FieldSelection();
		allRows.addRange(0, numComps + 1);
		selection.intersect(allRows);

		if (selection.getNumRanges() == 0) {
			this.selection.addRange(numComps, numComps + 1);
		}
		else if (isBlankLastLineSelected() && (getNumSelectedComponentRows() > 0)) {
			this.selection.removeRange(numComps, numComps + 1);
		}
		else {
			return false;
		}
		adjustCurrentRow();
		return true;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.CompositeEditorModel#setDataType(int, ghidra.program.model.data.DataType, int)
	 */
	protected void setDataType(int rowIndex, DataType dt, int length) throws UsrException {
		if (rowIndex < getNumComponents()) {
			replace(rowIndex, dt, length);
		}
		else {
			insert(rowIndex, dt, length);
		}
	}

	/**
	 * Validates that the data type indicated by the string can be set as the data type
	 * at the indicated row index. If the named data type can be various sizes, this
	 * method will prompt the user.
	 * @param rowIndex the row index
	 * @param dtString the string representing the data type.
	 * @return a valid data type instance or null if at blank line with no data type name.
	 * @throws UsrException indicating that the data type is not valid.
	 */
	@Override
	public DataTypeInstance validateComponentDataType(int rowIndex, String dtString)
			throws UsrException {
		dtString = DataTypeHelper.stripWhiteSpace(dtString);
		if ((dtString == null) || (dtString.length() < 1)) {
			if (rowIndex == getNumComponents()) {
				return null;
			}
		}
		return super.validateComponentDataType(rowIndex, dtString);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.EditorModel#isAddAllowed(ghidra.program.model.data.DataType)
	 */
	@Override
	public boolean isAddAllowed(DataType dataType) {
		int rowIndex = getMinIndexSelected();
		if (rowIndex == -1) {
			return false;
		}
		return isAddAllowed(rowIndex, dataType);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.CompositeEditorModel#isClearAllowed()
	 */
	@Override
	public boolean isClearAllowed() {
		return (getNumSelectedRows() > 0) && !isBlankLastLineSelected();
	}

	/**
	 * @param cycleGroup
	 * @return
	 */
	@Override
	public boolean isCycleAllowed(CycleGroup cycleGroup) {
		return (getNumSelectedRows() == 1);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.EditorModel#isInsertAllowed(ghidra.program.model.data.DataType)
	 */
	public boolean isInsertAllowed(DataType dataType) {
		int rowIndex = getMinIndexSelected();
		if (rowIndex == -1) {
			return false;
		}
		return isInsertAllowed(rowIndex, dataType);
	}

	/**
	 * Returns whether or not a component with the specified data type is allowed
	 * to be inserted before the component at the specified row index.
	 *
	 * @param rowIndex row index of the component in the structure.
	 * @param datatype the data type to be inserted.
	 */
	@Override
	public boolean isInsertAllowed(int rowIndex, DataType datatype) {
		return true;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.EditorModel#isReplaceAllowed(ghidra.program.model.data.DataType)
	 */
	public boolean isReplaceAllowed(DataType dataType) {
		if (getNumSelectedComponentRows() != 1) {
			return false;
		}
		int rowIndex = getMinIndexSelected();
		return isReplaceAllowed(rowIndex, dataType);
	}

	/**
	 * Deletes the ComponentDataType at the given index in this composite
	 * and removes the deleted component from the selection if necessary.
	 * <br> Note: this method does not fix the selection based on lock mode
	 * and does not perform any edit notification.
	 * @param componentOrdinal the ordinal of the component to be deleted.
	 */
	void delete(int componentOrdinal) {
		viewComposite.delete(componentOrdinal);
		if (componentOrdinal < row) {
			row--;
		}
		selection.removeRange(componentOrdinal, componentOrdinal + 1);
		adjustSelection(componentOrdinal + 1, -1);
		notifyCompositeChanged();
	}

	/**
	 * Delete the components at the specified indices.
	 * <br> Note: this method does not fix the selection based on lock mode
	 * and does not perform any edit notification.
	 *
	 * @param rows array with each row (component) index to delete.
	 */
	private void delete(int[] rows) {
		Arrays.sort(rows);
		for (int i = rows.length - 1; i >= 0; i--) {
			int rowIndex = rows[i];
			int componentOrdinal = convertRowToOrdinal(rowIndex);
			delete(componentOrdinal);
		}
	}

	/**
	 * Deletes the ComponentDataType at the given index in this composite,
	 * adjusts the selection, and fixes the selection according to the lock mode.
	 * It then notifies listeners the component was edited.
	 * @param rowIndex the index of the component to be deleted.
	 */
	@Override
	protected void deleteComponent(int rowIndex) {
		if (isEditingField()) {
			endFieldEditing();
		}
		int componentOrdinal = convertRowToOrdinal(rowIndex);
		delete(componentOrdinal);
		fixSelection();
		componentEdited();
		selectionChanged();
	}

	/**
	 *  Delete the named data types at the specified component indices.
	 *
	 * @param startRowIndex index of the starting row for the components to delete.
	 * @param endRowIndex index of the ending row (inclusive) for the components to delete.
	 */
	void deleteComponentRange(int startRowIndex, int endRowIndex) {
		if (isEditingField()) {
			endFieldEditing();
		}
		final int entries = endRowIndex - startRowIndex + 1;
		int[] ordinals = new int[entries];
		int ii = 0;
		for (int rowIndex = endRowIndex; rowIndex >= startRowIndex; rowIndex--, ++ii) {
			int componentOrdinal = convertRowToOrdinal(rowIndex);
			ordinals[ii] = componentOrdinal;
			if (componentOrdinal < row) {
				row--;
			}
			selection.removeRange(componentOrdinal, componentOrdinal + 1);
			adjustSelection(componentOrdinal + 1, -1);
		}
		viewComposite.delete(ordinals);
		fixSelection();
		componentEdited();
		notifyCompositeChanged();
		selectionChanged();
	}

	/**
	 *  Delete the selected components.
	 *
	 * @throws UsrException if the data type isn't allowed to be deleted.
	 */
	@Override
	public void deleteSelectedComponents() throws UsrException {
		if (!isDeleteAllowed()) {
			throw new UsrException("Deleting is not allowed.");
		}
		if (isEditingField()) {
			endFieldEditing();
		}
		int[] selectedComponents = getSelectedComponentRows();
		int firstRowIndex = !selection.isEmpty() ? selectedComponents[0] : getRowCount();
		delete(selectedComponents);
		componentEdited();
		selection.addRange(firstRowIndex, firstRowIndex + 1);
		fixSelection();
		selectionChanged();
	}

	/**
	 * Inserts a new datatype at the specified index into this composite
	 * and adjusts the selection.
	 * @param rowIndex the index where the new datatype is to be inserted.	
	 * @param dataType the datatype to insert.
	 * @param length the length to associate with the datatype.
	 * @param name the field name to associate with this component.
	 * @param comment the comment to associate with this component.
	 * @return the componentDataType created.
	 * @throws InvalidDataTypeException if the dataType.getLength() is positive 
	 * and does not match the given length parameter.
	 */
	protected abstract DataTypeComponent insert(int rowIndex, DataType dataType, int length,
			String name, String comment) throws InvalidDataTypeException;

	protected abstract void insert(int rowIndex, DataType dataType, int length, String name,
			String comment, int numCopies) throws InvalidDataTypeException;

	/**
	 * Add a DataType component into to an editable structure
	 *
	 * @param rowIndex index to place item(s) before.
	 *              use 0 to insert at front of a structure.
	 * @param dataType data type to be inserted into the structure
	 * @param dtLen the length of the data type
	 * @param multiple number of copies of the item to be added.
	 *
	 * @throws NoSuchElementException if there is no component with the specified index.
	 * @throws InvalidDataTypeException if the structure being edited is part
	 *         of the data type being inserted.
	 */
	protected void insertMultiple(int rowIndex, DataType dataType, int dtLen, int multiple)
			throws java.util.NoSuchElementException, InvalidDataTypeException {
		if (multiple < 1) {
			return;
		}

		insert(rowIndex, dataType, dtLen, null, null, multiple);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.EditorModel#insert(ghidra.program.model.data.DataType)
	 */
	@Override
	public DataTypeComponent insert(DataType dataType) throws UsrException {
		if (hasSelection()) {
			return insert(getMinIndexSelected(), dataType);
		}
		return null;
	}

	/**
	 * Inserts the specified data type at the specified component index.
	 *
	 * @param rowIndex the component index of where to add the data type.
	 * @param dt the data type to add
	 *
	 * @return true if the component is inserted, false if it doesn't.
	 * @throws UsrException if insert fails
	 */
	@Override
	public DataTypeComponent insert(int rowIndex, DataType dt) throws UsrException {
		return insert(rowIndex, dt, dt.getLength());
	}

	/**
	 *  Insert the named data type before the specified index.
	 *  Returns null, if the inserted component is an Undefined byte 
	 *  and it gets consumed by the component before it.
	 *
	 * @param rowIndex index of the row (component).
	 *
	 * @throws InvalidDataTypeException if the structure being edited is part
	 *         of the data type being inserted or if inserting isn't allowed.
	 * @throws DataTypeConflictException if creating the data type or one of
	 *         its sub-parts conflicted with an existing data type.
	 */
	@Override
	public DataTypeComponent insert(int rowIndex, DataType datatype, int length)
			throws UsrException {

		if (isEditingField()) {
			endFieldEditing();
		}
		checkIsAllowableDataType(datatype, true);
		if (length < 1) {
			DataTypeInstance dti = DataTypeHelper.getSizedDataType(getProvider(), datatype,
				lastNumBytes, Integer.MAX_VALUE);
			if (dti == null) {
				return null;
			}
			datatype = dti.getDataType();
			length = dti.getLength();
		}
		DataTypeComponent dtc = insert(rowIndex, datatype, length, null, null);
		fixSelection();
		componentEdited();
		selectionChanged();
		return dtc;
	}

	/**
	 * Add a DataType component into to an editable structure
	 *
	 * @param rowIndex index to place item(s) before.
	 *              use 0 to insert at front of a structure.
	 * @param dataType data type to be inserted into the structure
	 * @param dtLen the length of the data type
	 * @param multiple number of copies of the item to be added.
	 *
	 * @throws NoSuchElementException if there is no component with the specified index.
	 * @throws InvalidDataTypeException if the structure being edited is part
	 *         of the data type being inserted.
	 */
	protected void insertComponentMultiple(int rowIndex, DataType dataType, int dtLen, int multiple)
			throws java.util.NoSuchElementException, InvalidDataTypeException {
		if (isEditingField()) {
			endFieldEditing();
		}
		checkIsAllowableDataType(dataType, true);
		insertMultiple(rowIndex, dataType, dtLen, multiple);
		fixSelection();
		componentEdited();
		selectionChanged();
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.EditorModel#add(ghidra.program.model.data.DataType)
	 */
	@Override
	public DataTypeComponent add(DataType dataType) throws UsrException {
		if (isContiguousSelection()) {
			return add(getMinIndexSelected(), dataType);
		}
		return null;
	}

	/**
	 * Adds the specified data type at the specified component index. Whether
	 * an insert or replace occurs depends on whether the indicated index is
	 * in a selection and whether in locked or unlocked mode.
	 *
	 * @param rowIndex the index of the row where the data type should be added.
	 * @param dt the data type to add
	 *
	 * @return true if the component is added, false if it doesn't.
	 * @throws UsrException if add fails
	 */
	@Override
	public DataTypeComponent add(int rowIndex, DataType dt) throws UsrException {
		dt = viewDTM.resolve(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
		try {
			DataTypeInstance dti = getDropDataType(rowIndex, dt);
			return add(rowIndex, dti.getDataType(), dti.getLength());
		}
		catch (CancelledException e) {
			return null;
		}
	}

	/**
	 * Adds the specified data type at the specified component index. Whether
	 * an insert or replace occurs depends on whether the indicated index is
	 * in a selection and whether in locked or unlocked mode.
	 *
	 * @param rowIndex the index of the row where the data type should be added.
	 * @param dt the data type to add
	 *
	 * @return true if the component is added, false if it doesn't.
	 * @throws UsrException if add fails
	 */
	@Override
	public DataTypeComponent add(int rowIndex, DataType dt, int dtLength) throws UsrException {
		DataTypeComponent dtc = null;
		if (rowIndex < getNumComponents()) {
			FieldRange range = getSelectedRangeContaining(rowIndex);
			if ((range == null) ||
				(range.getStart().getIndex().intValue() == range.getEnd().getIndex().intValue() -
					1)) {
				dtc = replace(rowIndex, dt, dtLength);
			}
			else {
				dtc = replaceComponentRange(range.getStart().getIndex().intValue(),
					range.getEnd().getIndex().intValue() - 1, dt, dtLength);
			}
		}
		else {
			dtc = insert(rowIndex, dt, dtLength);
		}
		return dtc;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.EditorModel#replace(ghidra.program.model.data.DataType)
	 */
	public DataTypeComponent replace(DataType dataType) throws UsrException {
		if (isContiguousComponentSelection()) {
			return replace(getMinIndexSelected(), dataType);
		}
		return null;
	}

	/**
	 * Adds the specified data type at the specified component index. Whether
	 * an insert or replace occurs depends on whether the indicated index is
	 * in a selection and whether in locked or unlocked mode.
	 *
	 * @param rowIndex the index of row where the data type should be replaced.
	 * @param dt the new data type
	 *
	 * @return true if the component is added, false if it doesn't.
	 * @throws UsrException if add fails
	 */
	public DataTypeComponent replace(int rowIndex, DataType dt) throws UsrException {
		DataTypeInstance dti = DataTypeHelper.getFixedLength(this, rowIndex, dt);
		if (dti == null) {
			return null; // User cancelled from size dialog.
		}
		DataTypeComponent dtc = null;
		if (rowIndex < getNumComponents()) {
			FieldRange range = getSelectedRangeContaining(rowIndex);
			if ((range == null) ||
				(range.getStart().getIndex().intValue() == range.getEnd().getIndex().intValue() -
					1)) {
				dtc = replace(rowIndex, dti.getDataType(), dti.getLength());
			}
			else {
				dtc = replaceComponentRange(range.getStart().getIndex().intValue(),
					range.getEnd().getIndex().intValue() - 1, dti.getDataType(), dti.getLength());
			}
		}
		return dtc;
	}

	/**
	 * Replaces the current component at the specified index with one that
	 * is the indicated data type and size. It also sets the new component's 
	 * name and comment as indicated.
	 * @param rowIndex the index of row where the data type should be replaced.
	 * @param dataType the new datatype.
	 * @param length the length to associate with the datatype.
	 * @param name the field name to associate with this component.
	 * @param comment the comment to associate with this component.
	 * @return the componentDataType created.
	 * @throws InvalidDataTypeException if the dataType.getLength() is positive 
	 * and does not match the given length parameter.
	 */
	protected abstract DataTypeComponent replace(int rowIndex, DataType dataType, int length,
			String name, String comment) throws InvalidDataTypeException;

	/**
	 *  Replace the structure components from the start index to the end index
	 *  (inclusive) with as many of the specified data type as will fit.
	 *  Pad any left over bytes as undefineds.
	 *
	 * @param startRowIndex index of the first row (component) to replace.
	 * @param endRowIndex index of the last row (component) to replace.
	 * @param datatype the new data type
	 *
	 * @throws InvalidDataTypeException if the structure being edited is part
	 *         of the data type being inserted.
	 * @throws InsufficientBytesException if ther aren't enough bytes in the
	 * specified range.
	 */
	protected abstract boolean replaceRange(int startRowIndex, int endRowIndex, DataType datatype,
			int length) throws InvalidDataTypeException, InsufficientBytesException;

	/**
	 * Replaces the component at the indicated index.
	 * The existing fieldname and comment are retained.
	 * The selection is adjusted and change notification occurs.
	 * @param rowIndex
	 * @param datatype
	 * @return
	 * @throws InvalidDataTypeException
	 */
	@Override
	public DataTypeComponent replace(int rowIndex, DataType datatype, int length)
			throws UsrException {

		if (isEditingField()) {
			endFieldEditing();
		}

		if (rowIndex == getNumComponents()) {
			// Insert if at blank last line.
			return insert(rowIndex, datatype, length);
		}

		// Get the current data type at the index.
		DataTypeComponent oldDtc = getComponent(rowIndex);
		if (oldDtc == null) {
			// TODO should this throw exception instead?
			return null;
		}

		checkIsAllowableDataType(datatype, !oldDtc.isFlexibleArrayComponent());

		DataTypeComponent dtc;
		if (oldDtc.isFlexibleArrayComponent()) {
			// flexible array only supports fixed-length types
			dtc = replace(rowIndex, datatype);
		}
		else {
			int oldCompSize = oldDtc.getLength();
			int newCompSize = length;
			int sizeDiff = newCompSize - oldCompSize;

			// New one is larger so check to make sure it will fit.
			if (sizeDiff > 0) {
				if (!checkForReplace(rowIndex, datatype)) {
					throw new InvalidDataTypeException(datatype.getDisplayName() + " doesn't fit.");
				}
			}

			// Replace the component at index.
			dtc = replace(rowIndex, datatype, newCompSize, oldDtc.getFieldName(),
				oldDtc.getComment());
		}
		fixSelection();
		componentEdited();
		selectionChanged();
		return dtc;
	}

	/**
	 * Replaces the range of components between the start and end index (inclusive).
	 * The existing fieldname and comment are retained for the component at startIndex.
	 * The selection is adjusted and change notification occurs.
	 * @param startRowIndex
	 * @param endRowIndex
	 * @param datatype
	 * @param length
	 * @return
	 * @throws InvalidDataTypeException
	 * @throws InsufficientBytesException
	 */
	protected DataTypeComponent replaceComponentRange(int startRowIndex, int endRowIndex,
			DataType datatype, int length) throws UsrException {
		if (isEditingField()) {
			endFieldEditing();
		}

		if (!isShowingUndefinedBytes() && (startRowIndex == getNumComponents())) {
			// Insert if at blank last line.
			return insert(startRowIndex, datatype, length);
		}

		DataTypeComponent oldDtc = getComponent(startRowIndex);
		if (oldDtc == null || oldDtc.isFlexibleArrayComponent()) {
			throw new AssertException();
		}

		checkIsAllowableDataType(datatype, true);

		replaceRange(startRowIndex, endRowIndex, datatype, length);
		DataTypeComponent dtc = getComponent(startRowIndex);
		// Set the fieldname and comment the same as before
		try {
			dtc.setFieldName(oldDtc.getFieldName());
		}
		catch (DuplicateNameException exc) {
			Msg.showError(this, null, null, null);
		}
		dtc.setComment(oldDtc.getComment());
		fixSelection();
		componentEdited();
		selectionChanged();
		return dtc;
	}

	/**
	 *  Check to see if the specified data type fits in place of the data type
	 *  at the specified index of the data structure.<BR>
	 *  If the new data type is smaller, then it can replace the current one.<BR>
	 *  If the new data type is larger, then replace if we have enough
	 *  undefined bytes following the specified index.
	 *
	 * @param rowIndex index of the row (component).
	 */
	boolean checkForReplace(int rowIndex, DataType datatype) {
		DataTypeComponent dtc = getComponent(rowIndex);
		if (dtc == null) {
			return false;
		}
		if (!isShowingUndefinedBytes() || dtc.isFlexibleArrayComponent()) {
			return true;
		}
		// Does the new data type fit by replacing the component at index.

		// Get the current data type at the index.
		DataTypeComponent comp = getComponent(rowIndex);
		int currentCompSize = comp.getLength();
		int newCompSize = datatype.getLength();
		int sizeDiff = newCompSize - currentCompSize;
		int numUndefs = 0;

		// New one is larger.
		if (sizeDiff > 0) {
			if (isAtEnd(rowIndex) || onlyUndefinedsUntilEnd(rowIndex + 1)) {
				return true;
			}
			// structure needs to have enough undefined bytes or replace fails.
			numUndefs = getNumUndefinedBytesAt(rowIndex + 1);
		}

		return (sizeDiff <= numUndefs);
	}

	/**
	 * Replaces the components of the original structure with those of the edited one.
	 */
	protected abstract void replaceOriginalComponents();

	@Override
	protected void checkIsAllowableDataType(DataType datatype, boolean dynamicSizingAllowed)
			throws InvalidDataTypeException {

		super.checkIsAllowableDataType(datatype, dynamicSizingAllowed);

		// Verify that we aren't adding this structure or anything that it is
		// part of to this editable structure.
		if (datatype.equals(viewComposite)) {
			String msg = "Data type \"" + datatype.getDisplayName() + "\" can't contain itself.";
			throw new InvalidDataTypeException(msg);
		}
		else if (DataTypeUtilities.isSecondPartOfFirst(datatype, viewComposite)) {
			String msg = "Data type \"" + datatype.getDisplayName() + "\" has \"" +
				viewComposite.getDisplayName() + "\" within it.";
			throw new InvalidDataTypeException(msg);
		}
	}

	/**
	 *  Moves the components between the start index (inclusive) and the end
	 *  index (exclusive) to the new index (relative to the initial component set).
	 *
	 * @param startRowIndex index of the starting component to move.
	 * @param endRowIndex index of the ending component to move.
	 * @return true if components are moved.
	 */
	private boolean shiftComponentsUp(int startRowIndex, int endRowIndex) {
		int numComps = getNumComponents();
		if ((startRowIndex > endRowIndex) || startRowIndex <= 0 || startRowIndex >= numComps ||
			endRowIndex <= 0 || endRowIndex >= numComps) {
			return false;
		}
		DataTypeComponent comp = getComponent(startRowIndex - 1);
		deleteComponent(startRowIndex - 1);
		try {
			insert(endRowIndex, comp.getDataType(), comp.getLength(), comp.getFieldName(),
				comp.getComment());
		}
		catch (InvalidDataTypeException e) {
			return false;
		}
		return true;
	}

	/**
	 *  Moves the components between the start index (inclusive) and the end
	 *  index (exclusive) to the new index (relative to the initial component set).
	 *
	 * @param startRowIndex index of the starting component to move.
	 * @param endRowIndex index of the ending component to move.
	 * @return true if components are moved.
	 */
	private boolean shiftComponentsDown(int startRowIndex, int endRowIndex) {
		int numComps = getNumComponents();
		if ((startRowIndex > endRowIndex) || startRowIndex < 0 || startRowIndex >= numComps - 1 ||
			endRowIndex < 0 || endRowIndex >= numComps - 1) {
			return false;
		}
		DataTypeComponent comp = getComponent(endRowIndex + 1);
		deleteComponent(endRowIndex + 1);
		try {
			insert(startRowIndex, comp.getDataType(), comp.getLength(), comp.getFieldName(),
				comp.getComment());
		}
		catch (InvalidDataTypeException e) {
			return false;
		}
		return true;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.EditorModel#moveUp()
	 */
	@Override
	public boolean moveUp() throws NoSuchElementException {
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
		int newIndex = startIndex - 1;
		moved = shiftComponentsUp(startIndex, endIndex);
		if (moved) {
			componentEdited();
			FieldSelection tmpFieldSelection = new FieldSelection();
			tmpFieldSelection.addRange(newIndex, newIndex + numSelected);
			setSelection(tmpFieldSelection);
		}
		return moved;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.EditorModel#moveDown()
	 */
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

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.EditorModel#duplicateMultiple(int, int)
	 */
	@Override
	public void duplicateMultiple(int rowIndex, int multiple) throws UsrException {
		DataTypeComponent originalComp = getComponent(rowIndex);
		DataType dt = originalComp.getDataType();
		int dtLen = originalComp.getLength();

		try {
			insertComponentMultiple(rowIndex + 1, dt, dtLen, multiple);
		}
		catch (OutOfMemoryError memExc) {
			throw memExc; // rethrow the exception.
		}

		componentEdited();
		lastNumDuplicates = multiple;
	}

	/**
	 *  Clear the components at the specified indices.
	 *
	 * @param rows ordered array of the selected row's indices.
	 * @throws UsrException if clearing isn't allowed.
	 */
	@Override
	public abstract void clearComponents(int[] rows) throws UsrException;

	@Override
	protected void createArray(int numElements)
			throws InvalidDataTypeException, DataTypeConflictException, UsrException {
		if (selection.getNumRanges() != 1) {
			throw new UsrException("Can only create arrays on a contiguous selection.");
		}
		int rowIndex = selection.getFieldRange(0).getStart().getIndex().intValue();
		DataTypeComponent comp = getComponent(rowIndex);
		if (comp == null) {
			throw new UsrException("A component must be selected.");
		}
		if (isEditingField()) {
			endFieldEditing();
		}

		// Get data type to make into array.
		DataType dt = comp.getDataType();

		if (numElements == 0) {
			// assume if 0 was permitted flexible array support has been provided
			convertToFlexibleArray(rowIndex);
			return;
		}

		ArrayDataType array = new ArrayDataType(dt, numElements, comp.getLength(), viewDTM);

		if (getNumSelectedComponentRows() > 1) {
			replaceComponentRange(rowIndex,
				selection.getFieldRange(0).getEnd().getIndex().intValue() - 1, array,
				array.getLength());
		}
		else {
			replace(rowIndex, array, array.getLength()); // Can throw UsrException.
		}
	}

	/**
	 * Returns the number of undefined bytes that are available in the structure
	 * beginning at the specified row index.
	 *
	 * @param rowIndex the index of the row
	 */
	protected int getNumUndefinedBytesAt(int rowIndex) {
		int numRowComponents = getNumComponents();
		if (rowIndex < 0 || rowIndex >= numRowComponents) {
			return 0;
		}
		DataTypeComponent startComponent = getComponent(rowIndex);
		int previousOffset = (startComponent != null) ? startComponent.getOffset() : 0;
		for (int currentRowIndex =
			rowIndex; currentRowIndex < numRowComponents; currentRowIndex++) {
			// Get the current data type at the index.
			DataTypeComponent comp = getComponent(currentRowIndex);
			DataType dt = comp.getDataType();
			int currentOffset = comp.getOffset();
			if (!dt.equals(DataType.DEFAULT)) {
				return currentOffset - previousOffset; // Ran into data type other than undefined byte.
			}
		}

		return viewComposite.getLength() - previousOffset;
	}

	/**
	 * Determine if the indicated row index is at or beyond the last component in this composite.
	 *
	 * @param rowIndex the index of the row
	 * @return true if the index is at or beyond the last component.
	 */
	protected boolean isAtEnd(int rowIndex) {
		int numRowComponents = getNumComponents();
		if (rowIndex < 0) {
			return false;
		}
		if (rowIndex >= numRowComponents) {
			return true; // Beyond last component.
		}
		if (rowIndex + 1 == numRowComponents) {
			// On last displayed component.
			return true;
		}
		return false;
	}

	/**
	 * Determine whether or not there are only undefined data types from the indicated rowIndex
	 * until the end of the composite. There must be at least one undefined data type to return true.
	 *
	 * @param rowIndex the index of the row to begin checking for undefined data types.
	 * @return true if an undefined data type is at the indicated row index and all componnents 
	 * from there to the end of the composite are undefined data types.
	 */
	protected boolean onlyUndefinedsUntilEnd(int rowIndex) {
		if (!isShowingUndefinedBytes()) {
			return false;
		}
		int numRowComponents = getNumComponents();
		if (rowIndex < 0) {
			return false;
		}
		if (rowIndex >= numRowComponents) {
			return false; // Beyond last component.
		}
		for (int i = rowIndex; i < numRowComponents; i++) {
			// Get the current data type at the index.
			DataTypeComponent comp = getComponent(i);
			DataType dt = comp.getDataType();
			if (!dt.equals(DataType.DEFAULT)) {
				return false; // Ran into data type other than undefined byte.
			}
		}
		return true;
	}

	/**
	 * Cause the component at the specified index to consume undefined bytes
	 * that follow it.
	 * Note: this method adjusts the selection.
	 * @return the number of Undefined bytes consumed.
	 */
	protected int consumeByComponent(int rowIndex) {
		// TODO FIXME
		int numComps = viewComposite.getNumComponents();
		if (rowIndex >= 0 && rowIndex < numComps) {
			DataTypeComponent comp = viewComposite.getComponent(rowIndex);
			int compLen = comp.getLength();
			DataType dt = comp.getDataType();
			int dtLen = dt.getLength();
			// Data type is larger than component size.
			if (dtLen > compLen) {
				// See if undefined bytes were consumed by the component.
				viewComposite.dataTypeSizeChanged(dt);
				comp = viewComposite.getComponent(rowIndex);
				int diff = comp.getLength() - compLen;
				if (diff > 0) {
					int first = rowIndex + 1;
					int last = rowIndex + diff;
					selection.removeRange(first, last);
					adjustSelection(first, 0 - diff);
				}
				return diff;
			}
		}
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
	protected int consumeUndefinedBytes(int rowIndex, int numDesired)
			throws NoSuchElementException, InvalidDataTypeException {
		// TODO FIXME
		if (numDesired <= 0) {
			return 0;
		}
		int numRowComponents = getNumComponents();
		int numAvailable = getNumUndefinedBytesAt(rowIndex);
		int numIndicesRemoved = 0;
		if (numDesired > numAvailable) {
			throw new InvalidDataTypeException("Not enough undefined bytes."); // don't have enough undefined bytes there.
		}

		int numBytesNeeded = numDesired;
		if (rowIndex >= numRowComponents) {
			throw new NoSuchElementException();
		}

		for (int i = rowIndex; i < numRowComponents; i++) {
			// Get the current data type at the index.
			DataTypeComponent comp = viewComposite.getComponent(rowIndex);
			DataType dt = comp.getDataType();
			int compLength = 0;
			// A single undefined byte.
			if (dt == DataType.DEFAULT) {
				compLength = comp.getLength();
			}
			else {
				throw new InvalidDataTypeException("Not enough undefined bytes."); // Ran into data type other than undefined byte.
			}
			if (compLength < numBytesNeeded) {
				// consume all of this undefined bytes data type.
				numBytesNeeded -= compLength;
				deleteComponent(rowIndex);
				numIndicesRemoved++;
			}
			else {
				// Determine number of bytes left over.
				int leftOverBytes = compLength - numBytesNeeded;
				deleteComponent(rowIndex);
				numIndicesRemoved++;
				if (leftOverBytes == 1) {
					insert(rowIndex, DataType.DEFAULT, 1, null, null);
					numIndicesRemoved--;
				}
				else if (leftOverBytes > 1) {
					DataType newDt = new ArrayDataType(DataType.DEFAULT, leftOverBytes, 1, viewDTM);
					insert(rowIndex, newDt, leftOverBytes, null, null);
					numIndicesRemoved--;
				}
				break; // We're done.
			}
		}
		return numIndicesRemoved;
	}

	/**
	 * Unpackage the selected component in the structure or array. This means replace the structure
	 * with the data types for its component parts. For an array replace the array with the data type 
	 * for each array element.
	 * If the component isn't a structure or union then returns false.
	 * @return true if unpackage succeeded.
	 *
	 * @throws UsrException if the component can't be unpackaged.
	 */
	@Override
	public void unpackage(int rowIndex) throws UsrException {
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

		// Get the fieldname and comment before removing.
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
					insertMultiple(rowIndex, dt, elementLen, numComps);
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
				deleteComponent(rowIndex);
				try {
					// Add the structure's elements
					for (int i = 0; i < numComps; i++) {
						DataTypeComponent dtc = struct.getComponent(i);
						insert(rowIndex + i, dtc.getDataType(), dtc.getLength(), dtc.getFieldName(),
							dtc.getComment());
					}
				}
				catch (OutOfMemoryError memExc) {
					throw memExc; // re-throw the exception.
				}
			}
		}
		selection.clear();
		selection.addRange(rowIndex, rowIndex + numComps);

		DataTypeComponent comp = getComponent(rowIndex);
		// Set the field name and comment the same as before
		try {
			comp.setFieldName(fieldName);
		}
		catch (DuplicateNameException exc) {
			Msg.showError(this, null, null, null);
		}
		comp.setComment(comment);

		fixSelection();
		componentEdited();
		selectionChanged();
	}

	/**
	 * Returns the number of component rows in the editor. If unlocked, there 
	 * is a blank row at the end for inserting. Therefore this number can be
	 * different than the actual number of components currently in the
	 * structure being edited.
	 *
	 * @return the number of rows in the model
	 */
	@Override
	public int getRowCount() {
		int numRows = 0;
		if (viewComposite != null) {
			numRows = viewComposite.getNumComponents();
		}
		if (!isShowingUndefinedBytes()) {
			numRows++;
		}
		return numRows;
	}

	/**
	 *  This updates one of the values for a component that is a field of
	 *  this data structure.
	 *  @param aValue the new value for the field
	 *  @param rowIndex the index of the row for the component
	 *  @param modelColumnIndex the model field index within the component
	 */
	@Override
	public void setValueAt(Object aValue, int rowIndex, int modelColumnIndex) {
		try {
			settingValueAt = true;
			if (fieldEdited(aValue, rowIndex, modelColumnIndex)) {
				componentEdited();
			}
		}
		finally {
			settingValueAt = false;
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.EditorModel#setComponentDataType(int, ghidra.program.model.data.DataType, int)
	 */
	@Override
	public void setComponentDataTypeInstance(int rowIndex, DataTypeInstance dti)
			throws UsrException {
		if (getComponent(rowIndex) == null) {
			// Replacing data type in unlocked mode replaces only
			// that data type and structure size may change.
			insert(rowIndex, dti.getDataType(), dti.getLength());
		}
		else {
			// Replacing data type in unlocked mode replaces only
			// that data type and structure size may change.
			replace(rowIndex, dti.getDataType(), dti.getLength());
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.CompositeEditorModel#validateComponentName(int, java.lang.String)
	 */
	@Override
	public void validateComponentName(int rowIndex, String name) throws UsrException {
		if (nameExistsElsewhere(name, rowIndex)) {
			throw new InvalidNameException("Name \"" + name + "\" already exists.");
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.EditorModel#setComponentName(int, java.lang.String)
	 */
	@Override
	public void setComponentName(int rowIndex, String name)
			throws InvalidInputException, InvalidNameException, DuplicateNameException {
		if (name.equals("")) {
			name = null;
		}
		if (nameExistsElsewhere(name, rowIndex)) {
			throw new InvalidNameException("Name \"" + name + "\" already exists.");
		}
		try {
			getComponent(rowIndex).setFieldName(name);
		}
		catch (DuplicateNameException exc) {
			throw new InvalidNameException(exc.getMessage());
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.EditorModel#setComponentComment(int, java.lang.String)
	 */
	@Override
	public void setComponentComment(int rowIndex, String comment) throws InvalidInputException {
		if (comment.equals("")) {
			comment = null;
		}
		getComponent(rowIndex).setComment(comment);
		fireTableCellUpdated(rowIndex, getCommentColumn());
		componentDataChanged();
	}

	/**
	 * Returns whether the selected component(s) can be moved up (to the next lower index).
	 */
	@Override
	public boolean isMoveUpAllowed() {
		if (!isContiguousSelection())
			return false;
		int start = selection.getFieldRange(0).getStart().getIndex().intValue();
		return ((start > 0) && (start < getNumComponents()));
	}

	/**
	 * Returns whether the selected component(s) can be moved down (to the next higher index).
	 */
	@Override
	public boolean isMoveDownAllowed() {
		return (isContiguousSelection() &&
			(selection.getFieldRange(0).getEnd().getIndex().intValue() < getNumComponents()));
	}

	// *************************************************************
	// End of methods for determining if a type of edit action is allowed.
	// *************************************************************

	// *************************************************************
	// Override CompositeViewerModel CategoryChangeListener methods
	// *************************************************************

	@Override
	public void dataTypeChanged(DataTypeManager dtm, DataTypePath path) {
		try {

			if (isLoaded()) {
				// If we don't currently have any modifications that need applying and
				// the structure in the editor just changed, then show the changed
				// structure.
				if (originalDataTypePath == null) {
					return;
				}
				String oldName = path.getDataTypeName();
				if (path.equals(originalDataTypePath)) {
					if (consideringReplacedDataType) {
						return;
					}
					// Return if the original is already changing. Need this since there
					// can be multiple change notifications from a single data type update 
					// event due to replaceWith(), setLastChangeTime() and 
					// setLastChangeTimeInSource() each firing dataTypeChanged().
					if (originalIsChanging) {
						return;
					}
					originalIsChanging = true;
					try {
						if (hadChanges) {
							String message = oldName + " has changed outside the editor.\n" +
								"Discard edits & reload the " + getTypeName() + "?";
							String title = "Reload " + getTypeName() + " Editor?";
							int response = OptionDialog.showYesNoDialogWithNoAsDefaultButton(
								provider.getComponent(), title, message);
							if (response == OptionDialog.OPTION_ONE) {
								load(getOriginalComposite());
							}
							originalComponentsChanged();
						}
						else {
							Composite changedComposite = getOriginalComposite();
							if ((changedComposite != null) &&
								!viewComposite.isEquivalent(changedComposite)) {
								load(getOriginalComposite());
								setStatus(
									viewComposite.getPathName() + " changed outside the editor.",
									false);
							}
						}
					}
					finally {
						originalIsChanging = false;
					}
				}
				else {
					DataType viewDt = viewDTM.getDataType(path);
					if (viewDt == null) {
						return;
					}
					int origDtLen = viewDt.getLength();
					DataType changedDt = dtm.getDataType(path);
					if (changedDt != null) {
						if ((viewDt instanceof Composite) && (changedDt instanceof Composite)) {
							Composite comp = (Composite) changedDt;
							Composite origDt = getOriginalComposite();
							if ((origDt != null) && comp.isPartOf(origDt)) {
								removeDtFromComponents(comp);
							}

							((Composite) viewDt).setDescription(
								((Composite) changedDt).getDescription());
						}
						viewDt =
							viewDTM.resolve(changedDt, DataTypeConflictHandler.REPLACE_HANDLER);
						if (origDtLen != viewDt.getLength()) {
							viewComposite.dataTypeSizeChanged(viewDt);
						}
					}
					fireTableDataChanged();
					componentDataChanged();
				}
			}
		}
		catch (ConcurrentModificationException e) {
			// do nothing, the delete will fix things later
		}
	}

	private volatile boolean consideringReplacedDataType = false;

	@Override
	public void dataTypeReplaced(DataTypeManager dtm, DataTypePath oldPath, DataTypePath newPath,
			DataType newDataType) {
		if (newDataType == null) {
			return;
		}
		if (isLoaded()) {
			DataTypeManager originalDataTypeManager = getOriginalDataTypeManager();
			if (originalDataTypeManager != dtm) {
				return;
			}
			if (originalDataTypePath == null) {
				return;
			}
			String dtName = oldPath.getDataTypeName();
			DataTypePath dtPath = new DataTypePath(newDataType.getCategoryPath(), dtName);
			if (!dtPath.equals(originalDataTypePath)) {
				DataType dt = viewDTM.getDataType(dtPath);
				if (dt != null) {
					if (hasSubDt(viewComposite, dtPath)) {
						String msg = "Replaced data type \"" + dtPath +
							"\", which is a sub-component of \"" + getOriginalDataTypeName() +
							"\".";
						setStatus(msg, true);
					}
					try {
						viewDTM.replaceDataType(dt, newDataType, true);
					}
					catch (DataTypeDependencyException e) {
						throw new AssertException(e);
					}
					fireTableDataChanged();
					componentDataChanged();
				}
			}
			else {
				if (this.hadChanges) {
					if (originalDataTypePath.equals(oldPath)) {
						if (hadChanges) {
							consideringReplacedDataType = true;
							try {
								String message =
									oldPath.getPath() + " has changed outside the editor.\n" +
										"Discard edits & reload the " + getTypeName() + "?";
								String title = "Reload " + getTypeName() + " Editor?";
								int response = OptionDialog.showYesNoDialogWithNoAsDefaultButton(
									provider.getComponent(), title, message);
								if (response == OptionDialog.OPTION_ONE) {
									load(getOriginalComposite());
								}
								originalComponentsChanged();
							}
							finally {
								consideringReplacedDataType = false;
							}
						}
						else {
							load(getOriginalComposite());
							setStatus(viewComposite.getPathName() + " changed outside the editor.",
								false);
						}
					}
					else {
						String msg = "\"" + oldPath.getPath() + "\" was replaced with " +
							newDataType.getPathName() + " in the data type manager.";
						setStatus(msg, true);
					}
				}
				else {
					load((Composite) newDataType);
				}
			}
		}
	}

	// *** HELPER METHODS for use with CategoryChangeListener methods. ***
	/**
	 * Removes the indicated data type from any components to prevent a cycle
	 * being created by this component being updated. Structures will actually
	 * clear any components containing the indicated data type.
	 * Unions will delete their components that contain the data type.
	 * @param comp the composite data type that contains the data type being edited.
	 */
	abstract void removeDtFromComponents(Composite comp);

	// *************************************************************
	// End of Override CompositeViewerModel CategoryChangeListener methods
	// *************************************************************

	/* (non-Javadoc)
	 * @see javax.swing.table.AbstractTableModel#fireTableDataChanged()
	 */
	@Override
	public void fireTableDataChanged() {
		boolean tmpUpdatingSelection = updatingSelection;
		try {
			updatingSelection = true;
			super.fireTableDataChanged(); // This causes the table selection to go away.
			selectionChanged(); // This sets the selection back.
		}
		finally {
			updatingSelection = tmpUpdatingSelection;
		}
	}

	/**
	 * Determine the maximum number of duplicates that can be created for 
	 * the component at the indicated index. The duplicates would follow
	 * the component. The number allowed depends on how many fit based on 
	 * the current lock/unlock state of the editor.
	 * <br>Note: This method doesn't care whether there is a selection or not.
	 *
	 * @param rowIndex the index of the row for the component to be duplicated.
	 * @return the maximum number of duplicates. -1 indicates unlimited.
	 */
	@Override
	public int getMaxDuplicates(int rowIndex) {
		int numRowComponents = getNumComponents();
		if ((rowIndex < 0) || (rowIndex >= numRowComponents)) {
			return 0;
		}
		if (rowIndex + 1 == numRowComponents) {
			return Integer.MAX_VALUE; // On last component.
		}
		DataType dt = getComponent(rowIndex).getDataType();
		int maxDups = Integer.MAX_VALUE;
		// If editModel is showing undefined bytes (unaligned) 
		// then constrain by number of undefined bytes that follow.
		if (isShowingUndefinedBytes() && (dt != DataType.DEFAULT)) {
			int numBytes = getNumUndefinedBytesAt(rowIndex + 1);
			maxDups = (numBytes / dt.getLength());
		}
		return maxDups;
	}

	/**
	 * Determine the maximum number of array elements that can be created for 
	 * the current selection. The array data type is assumed to become the
	 * data type of the first component in the selection. The current selection
	 * must be contiguous or 0 is returned.
	 *
	 * @return the number of array elements that fit in the current selection.
	 */
	@Override
	public int getMaxElements() {
		if (!isContiguousSelection()) {
			return 0;
		}
		if (isFlexibleArraySelection()) {
			return Integer.MAX_VALUE;
		}

		int rowIndex = selection.getFieldRange(0).getStart().getIndex().intValue();
		if (rowIndex < getNumComponents()) {
			DataTypeComponent comp = getComponent(rowIndex);

			DataType dt = comp.getDataType();
			int len = dt.getLength() > 0 ? dt.getLength() : comp.getLength();

			FieldRange range = getSelectedRangeContaining(rowIndex);
			boolean singleLineSelection = (getNumSelectedComponentRows() == 1);

			// Selection exists.
			if ((range != null) && !singleLineSelection) {
				// Determine the number of bytes.
				int numBytesInRange = getNumBytesInRange(range);
				return numBytesInRange / len;
			}
			// single line selected.

			// If editModel is locked then constrain by number of undefined bytes that follow.
			if (!isShowingUndefinedBytes() || isAtEnd(rowIndex) ||
				onlyUndefinedsUntilEnd(rowIndex + 1)) {
				return Integer.MAX_VALUE;
			}

			int numBytes = getNumUndefinedBytesAt(rowIndex + 1);
			return 1 + (numBytes / len);
		}
		return 0;
	}

	/**
	 * Return the last number of duplicates the user entered when prompted for 
	 * creating duplicates of a component.
	 */
	@Override
	public int getLastNumDuplicates() {
		return lastNumDuplicates;
	}

	/**
	 * Called whenever the data structure's modification state changes.
	 */
	void componentEdited() {
		updateAndCheckChangeState(); // Update the composite's change state information.
		fireTableDataChanged();
		componentDataChanged();
	}

	protected int convertRowToOrdinal(int rowIndex) {
		return rowIndex;
	}

	public boolean isAligned() {
		return viewComposite.isInternallyAligned();
	}

	public void setAligned(boolean aligned) {
		boolean currentViewIsAligned = viewComposite.isInternallyAligned();
		if (currentViewIsAligned == aligned) {
			return;
		}
		viewComposite.setInternallyAligned(aligned);
		notifyCompositeChanged();
	}

	public int getPackingValue() {
		return viewComposite.getPackingValue();
	}

	protected boolean isSizeEditable() {
		return false;
	}

	@Override
	public boolean updateAndCheckChangeState() {
		if (originalIsChanging) {
			return false;
		}
		boolean compositeChanged = super.updateAndCheckChangeState();
		if (compositeChanged) {
			return true;
		}
		Composite oldComposite = getOriginalComposite();
		if (oldComposite == null) {
			hadChanges = false;
			return hadChanges;
		}
		hadChanges = !(viewComposite.isInternallyAligned() == oldComposite.isInternallyAligned() &&
			viewComposite.getPackingValue() == oldComposite.getPackingValue() &&
			viewComposite.isDefaultAligned() == oldComposite.isDefaultAligned() &&
			viewComposite.isMachineAligned() == oldComposite.isMachineAligned() &&
			viewComposite.getMinimumAlignment() == oldComposite.getMinimumAlignment());
		return hadChanges;
	}

	/**
	 *  Return the external (minimum) alignment type for the structure or union being viewed.
	 */
	public AlignmentType getMinimumAlignmentType() {
		if (viewComposite.isDefaultAligned()) {
			return AlignmentType.DEFAULT_ALIGNED;
		}
		if (viewComposite.isMachineAligned()) {
			return AlignmentType.MACHINE_ALIGNED;
		}
		return AlignmentType.ALIGNED_BY_VALUE;
	}

	/**
	 *  Return the external (minimum) alignment value for the structure or union being viewed.
	 */
	public int getMinimumAlignment() {
		if (viewComposite != null) {
			return viewComposite.getMinimumAlignment();
		}
		return 0;
	}

	public void setAlignmentType(AlignmentType alignmentType) throws InvalidInputException {
		if (alignmentType == AlignmentType.DEFAULT_ALIGNED) {
			viewComposite.setToDefaultAlignment();
		}
		else if (alignmentType == AlignmentType.MACHINE_ALIGNED) {
			viewComposite.setToMachineAlignment();
		}
		else {
			int alignment = viewComposite.getMinimumAlignment();
			if (alignment == 0) {
				alignment = viewDTM.getDataOrganization().getAlignment(viewComposite, getLength());
			}
			viewComposite.setMinimumAlignment(alignment); // Causes the type to change, but not the value.
		}
		notifyCompositeChanged();
	}

	public abstract void setAlignment(int alignmentValue) throws InvalidInputException;

	public void setPackingValue(int packingValue) throws InvalidInputException {
		int currentViewPackingValue = viewComposite.getPackingValue();
		if (currentViewPackingValue == packingValue) {
			return;
		}
		viewComposite.setPackingValue(packingValue);
		notifyCompositeChanged();
	}

	public int getActualAlignment() {
		return viewDTM.getDataOrganization().getAlignment(viewComposite, getLength());
	}

}
