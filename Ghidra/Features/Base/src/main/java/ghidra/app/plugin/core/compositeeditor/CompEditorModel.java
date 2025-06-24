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

import javax.help.UnsupportedOperationException;

import docking.widgets.OptionDialog;
import docking.widgets.fieldpanel.support.*;
import ghidra.program.database.DatabaseObject;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.InsufficientBytesException;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public abstract class CompEditorModel<T extends Composite> extends CompositeEditorModel<T> {

	private volatile boolean consideringReplacedDataType = false;

	/**
	 * Creates a model for editing a composite data type.
	 * @param provider the provider that is using this model for editing.
	 */
	CompEditorModel(CompositeEditorProvider<T, ? extends CompEditorModel<T>> provider) {
		super(provider);
	}

	@Override
	public boolean hasChanges() {
		if (originalDTM != null && !originalDTM.contains(originalComposite)) {
			return true;
		}
		return super.hasChanges();
	}

	/**
	 * Sets the data type that is being edited and the category where it will get saved.
	 * @param dataType the composite data type being edited.
	 */
	@Override
	public void load(T dataType) {
		super.load(dataType);
		fixSelection();
		selectionChanged();
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
		T originalDt = getOriginalComposite();
		if (originalDt == null || originalDTM == null) {
			throw new IllegalStateException(
				"Can't apply edits without a data type or data type manager.");
		}
		boolean originalDtExists = originalDTM.contains(originalDt);
		boolean renamed = false;
		if (originalDtExists) {
			String origName = originalDt.getName();
			String editName = getCompositeName();
			renamed = !origName.equals(editName);
		}
		String action = originalDtExists ? "Edit" : "Create";
		if (renamed) {
			action += "/Rename";
		}
		int transactionID = originalDTM.startTransaction(action + " " + getTypeName());
		try {
			if (originalDtExists) {
				// Update the original structure.
				if (renamed) {
					String editName = getCompositeName();
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
				updateOriginalComponentSettings(viewComposite, originalDt);
				load(originalDt);
			}
			else {
				@SuppressWarnings("unchecked")
				T dt = (T) originalDTM.resolve(viewComposite, null);
				load(dt);
			}
			return true;
		}
		finally {
			provider.updateTitle();
			setSelection(saveSelection);
			originalDTM.endTransaction(transactionID, true);
		}
	}

//==================================================================================================
// OVERRIDDEN METHODS FOR THE SELECTION
//==================================================================================================

	/**
	 * Returns true if the GUI has the blank last line selected
	 * @return true if the GUI has the blank last line selected
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
	 * @return the number of bytes
	 */
	protected abstract int getNumBytesInRange(FieldRange range);

	/**
	 * Saves the current selection in the components viewing area.
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
			for (int r : rows) {
				// Only add valid component rows (i.e. don't include blank last line)
				if (r < numComponents) {
					tmpSelection.addRange(r, r + 1);
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
		// This can happen due to switching between packed and non-packed.
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

//	@Override
//	public DataTypeInstance validateComponentDataType(int rowIndex, String dtString)
//			throws UsrException {
//		dtString = DataTypeHelper.stripWhiteSpace(dtString);
//		if ((dtString == null) || (dtString.length() < 1)) {
//			if (rowIndex == getNumComponents()) {
//				return null;
//			}
//		}
//		return super.validateComponentDataType(rowIndex, dtString);
//	}

	@Override
	public boolean isAddAllowed(DataType dataType) {
		int rowIndex = getMinIndexSelected();
		if (rowIndex == -1) {
			return false;
		}
		return isAddAllowed(rowIndex, dataType);
	}

	@Override
	public boolean isClearAllowed() {
		return (getNumSelectedRows() > 0) && !isBlankLastLineSelected();
	}

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
		doDelete(componentOrdinal);
		selection.removeRange(componentOrdinal, componentOrdinal + 1);
		adjustSelection(componentOrdinal + 1, -1);
		notifyCompositeChanged();
	}

	private void doDelete(int componentOrdinal) {
		viewDTM.withTransaction("Delete Component", () -> {
			viewComposite.delete(componentOrdinal);
		});
		if (componentOrdinal < currentEditRow) {
			currentEditRow--;
		}
	}

	/**
	 * Delete the components at the specified indices.
	 *
	 * <br> Note: this method does not fix the selection based on lock mode
	 * and does not perform any edit notification.
	 *
	 * @param rows array with each row (component) index to delete
	 * @throws CancelledException if cancelled
	 */
	private void delete(int[] rows) throws CancelledException {

		int n = rows.length;
		Arrays.sort(rows);

		Set<Integer> rowSet = new HashSet<>();

		for (int i = n - 1; i >= 0; i--) {
			int rowIndex = rows[i];
			int componentOrdinal = convertRowToOrdinal(rowIndex);
			if (componentOrdinal < currentEditRow) {
				currentEditRow--;
			}
			rowSet.add(componentOrdinal);
		}

		viewDTM.withTransaction("Delete Components", () -> viewComposite.delete(rowSet));

		// Not sure if this is the right behavior.  Assuming the deleted rows were selected,
		// restore the selection to be the first row that was deleted so that the UI leaves the
		// user's selection close to where it was.
		if (rows.length > 0) {
			setSelection(new int[] { rows[0] });
		}

		notifyCompositeChanged();

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
		selectionChanged();
	}

	/**
	 *  Delete the named data types at the specified component indices.
	 *
	 * @param startRowIndex index of the starting row for the components to delete.
	 * @param endRowIndex index of the ending row (inclusive) for the components to delete.
	 * @param monitor the task monitor
	 * @throws CancelledException if the work was cancelled
	 */
	void deleteComponentRange(int startRowIndex, int endRowIndex, TaskMonitor monitor)
			throws CancelledException {
		if (isEditingField()) {
			endFieldEditing();
		}

		final int entries = endRowIndex - startRowIndex + 1;
		Set<Integer> ordinals = new HashSet<>();

		monitor.initialize(entries);
		for (int rowIndex = endRowIndex; rowIndex >= startRowIndex; rowIndex--) {
			monitor.checkCancelled();
			int componentOrdinal = convertRowToOrdinal(rowIndex);
			ordinals.add(componentOrdinal);
			if (componentOrdinal < currentEditRow) {
				currentEditRow--;
			}
			selection.removeRange(componentOrdinal, componentOrdinal + 1);
			adjustSelection(componentOrdinal + 1, -1);
			monitor.incrementProgress(1);
		}
		viewDTM.withTransaction("Delete Components", () -> viewComposite.delete(ordinals));
		fixSelection();
		selectionChanged();
	}

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

	protected abstract void insert(int rowIndex, DataType dataType, int length, int numCopies,
			TaskMonitor monitor) throws InvalidDataTypeException, CancelledException;

	/**
	 * Add a DataType component into to an editable structure
	 *
	 * @param rowIndex index to place item(s) before.
	 *              use 0 to insert at front of a structure.
	 * @param dataType data type to be inserted into the structure
	 * @param dtLen the length of the data type
	 * @param multiple number of copies of the item to be added.
	 * @param monitor the task monitor
	 *
	 * @throws NoSuchElementException if there is no component with the specified index.
	 * @throws InvalidDataTypeException if the structure being edited is part
	 *         of the data type being inserted.
	 * @throws CancelledException if the work was cancelled
	 */
	protected void insertMultiple(int rowIndex, DataType dataType, int dtLen, int multiple,
			TaskMonitor monitor)
			throws NoSuchElementException, InvalidDataTypeException, CancelledException {
		if (multiple < 1) {
			return;
		}

		insert(rowIndex, dataType, dtLen, multiple, monitor);
	}

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
	 */
	@Override
	public DataTypeComponent insert(int rowIndex, DataType datatype, int length)
			throws InvalidDataTypeException, UsrException {

		if (isEditingField()) {
			endFieldEditing();
		}
		checkIsAllowableDataType(datatype);
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
	 * @param monitor the task monitor
	 *
	 * @throws NoSuchElementException if there is no component with the specified index.
	 * @throws InvalidDataTypeException if the structure being edited is part
	 *         of the data type being inserted.
	 * @throws CancelledException if the work was cancelled
	 */
	protected void insertComponentMultiple(int rowIndex, DataType dataType, int dtLen, int multiple,
			TaskMonitor monitor)
			throws NoSuchElementException, InvalidDataTypeException, CancelledException {
		if (isEditingField()) {
			endFieldEditing();
		}

		checkIsAllowableDataType(dataType);
		insertMultiple(rowIndex, dataType, dtLen, multiple, monitor);
		fixSelection();
		selectionChanged();
	}

	@Override
	public DataTypeComponent add(DataType dataType) throws UsrException {
		if (!isContiguousSelection()) {
			setStatus("Replace data type only works on a contiguous selection", true);
			return null;
		}
		return add(getMinIndexSelected(), dataType);
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
		String descr = rowIndex < getNumComponents() ? "Replace Component" : "Add Component";
		DataTypeComponent dtc = viewDTM.withTransaction(descr, () -> {
			DataType resolvedDt = viewDTM.resolve(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
			try {
				DataTypeInstance dti = getDropDataType(rowIndex, resolvedDt);
				return add(rowIndex, dti.getDataType(), dti.getLength()); // add or replace
			}
			catch (CancelledException e) {
				return null;
			}
		});

		fixSelection();
//		componentEdited();
		selectionChanged();
		return dtc;
	}

	/**
	 * Adds the specified data type at the specified component index. Whether
	 * an insert or replace occurs depends on whether the indicated index is
	 * in a selection and whether in locked or unlocked mode.
	 *
	 * @param rowIndex the index of the row where the data type should be added.
	 * @param dt the data type to add
	 * @param dtLength datatype instance length
	 * @return the component is added, null if it doesn't.
	 * @throws UsrException if add fails
	 */
	@Override
	public DataTypeComponent add(int rowIndex, DataType dt, int dtLength) throws UsrException {
		DataTypeComponent dtc = null;
		if (rowIndex < getNumComponents()) {
			dtc = viewDTM.withTransaction("Replace Component", () -> {
				FieldRange range = getSelectedRangeContaining(rowIndex);
				if ((range == null) || (range.getStart()
						.getIndex()
						.intValue() == range.getEnd().getIndex().intValue() - 1)) {
					return replace(rowIndex, dt, dtLength);
				}
				return replaceComponentRange(range.getStart().getIndex().intValue(),
					range.getEnd().getIndex().intValue() - 1, dt, dtLength);
			});
		}
		else {
			dtc = viewDTM.withTransaction("Add Component", () -> insert(rowIndex, dt, dtLength));
		}

		fixSelection();
		//componentEdited();
		selectionChanged();
		return dtc;
	}

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
	 * @return component added, null or exception if it does not
	 * @throws UsrException if add error occurs
	 */
	public DataTypeComponent replace(int rowIndex, DataType dt) throws UsrException {
		return viewDTM.withTransaction("Replace Component", () -> {
			DataTypeInstance dti =
				DataTypeHelper.getFixedLength(this, rowIndex, dt, usesAlignedLengthComponents());
			if (dti == null) {
				return null; // User cancelled from size dialog.
			}
			if (rowIndex < getNumComponents()) {
				FieldRange range = getSelectedRangeContaining(rowIndex);
				if ((range == null) || (range.getStart()
						.getIndex()
						.intValue() == range.getEnd().getIndex().intValue() - 1)) {
					return replace(rowIndex, dti.getDataType(), dti.getLength());
				}
				return replaceComponentRange(range.getStart().getIndex().intValue(),
					range.getEnd().getIndex().intValue() - 1, dti.getDataType(), dti.getLength());
			}
			return null;
		});
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
	 * Replace the structure components from the start index to the end index
	 * (inclusive) with as many of the specified data type as will fit.
	 * Pad any left over bytes as undefined bytes.
	 *
	 * @param startRowIndex index of the first row (component) to replace.
	 * @param endRowIndex index of the last row (component) to replace.
	 * @param datatype the new data type
	 * @param length the length of the range
	 * @param monitor the task monitor
	 * @return true if the replacement worked
	 *
	 * @throws InvalidDataTypeException if the structure being edited is part
	 *         of the data type being inserted
	 * @throws InsufficientBytesException if there aren't enough bytes in the specified range
	 * @throws CancelledException if the work is cancelled
	 */
	protected abstract boolean replaceRange(int startRowIndex, int endRowIndex, DataType datatype,
			int length, TaskMonitor monitor)
			throws InvalidDataTypeException, InsufficientBytesException, CancelledException;

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
			return null;
		}

		checkIsAllowableDataType(datatype);

		int oldCompSize = oldDtc.getLength();
		int newCompSize = length;
		int sizeDiff = newCompSize - oldCompSize;

		// New one is larger so check to make sure it will fit.
		if (!isAtEnd(rowIndex) && sizeDiff > 0) {
			checkForReplace(rowIndex, datatype, newCompSize);
		}

		// Replace the component at index.
		DataTypeComponent dtc =
			replace(rowIndex, datatype, newCompSize, oldDtc.getFieldName(), oldDtc.getComment());

		fixSelection();
		selectionChanged();
		return dtc;
	}

	/**
	 * Replaces the range of components between the start and end index (inclusive).
	 * The existing field name and comment are retained for the component at startIndex.
	 * The selection is adjusted and change notification occurs.
	 * @param startRowIndex the start index
	 * @param endRowIndex the end index
	 * @param datatype the data type
	 * @param length the length of the range
	 * @return the newly create component
	 * @throws UsrException if there is an exception replacing
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
		if (oldDtc == null) {
			throw new AssertException();
		}

		checkIsAllowableDataType(datatype);

		//
		// Note: if the range being replaced is large enough, then the UI could lock-up.  If we
		//       find that is the case, then we can update this method to take in a task monitor
		//       and update the clients accordingly.  For now, it does not seem worth the effort.
		//
		TaskMonitor monitor = TaskMonitor.DUMMY;

		replaceRange(startRowIndex, endRowIndex, datatype, length, monitor);
		DataTypeComponent dtc = getComponent(startRowIndex);

		// Set the field name and comment the same as before
		try {
			dtc.setFieldName(oldDtc.getFieldName());
		}
		catch (DuplicateNameException e) {
			Msg.showError(this, null, "Unexcected Exception", "Exception applying field name", e);
		}
		dtc.setComment(oldDtc.getComment());
		fixSelection();
		selectionChanged();
		return dtc;
	}

	/**
	 * Check to see if the specified data type fits in place of the data type
	 * at the specified index of the data structure.<BR>
	 * If the new data type is smaller, then it can replace the current one.<BR>
	 * If the new data type is larger, then replace if we have enough
	 * undefined bytes following the specified index.
	 *
	 * @param rowIndex index of the row (component).
	 * @param datatype the type
	 * @param length component length
	 * @throws InvalidDataTypeException if check fails
	 */
	private void checkForReplace(int rowIndex, DataType datatype, int length)
			throws InvalidDataTypeException {
		DataTypeComponent dtc = getComponent(rowIndex);
		if (dtc == null) {
			throw new InvalidDataTypeException("Invalid component selection");
		}
		if (!(viewComposite instanceof Structure struct)) {
			return;
		}
		if (struct.isPackingEnabled()) {
			return;
		}
		if (isAtEnd(rowIndex)) {
			return;
		}

		// Does the new data type fit by replacing the component at index.

		// Get the current data type at the index.
		int currentCompSize = dtc.getLength();
		int newCompSize = length;
		int sizeDiff = newCompSize - currentCompSize;

		if (sizeDiff <= 0) {
			return;
		}

		int undefinedSpaceAvail = getNumUndefinedBytesAfter(dtc);
		if (sizeDiff > undefinedSpaceAvail) {
			int spaceNeeded = sizeDiff - undefinedSpaceAvail;
			String msg =
				newCompSize + " byte replacement at 0x" + Integer.toHexString(dtc.getOffset());
			if (struct.getDefinedComponentAtOrAfterOffset(dtc.getOffset() + 1) == null) {
				// suggest growing structure
				int suggestedSize = getLength() + spaceNeeded;
				throw new InvalidDataTypeException(
					msg + " requires structure length of " + suggestedSize + "-bytes.");
			}
			// suggest insert bytes (NOTE: in the future a conflict removal/grow could be offered)
			throw new InvalidDataTypeException(
				msg + " requires " + spaceNeeded + " additional undefined bytes.");
		}
	}

	/**
	 * Get the number of undefined bytes after the specified component.
	 * The viewComposite must be a non-packed structure.
	 * @param dtc datatype component
	 * @return number of undefined bytes after non-packed structure component or -1 if no additional
	 * defined components exist which will impead component growth or placement. 
	 */
	protected final int getNumUndefinedBytesAfter(DataTypeComponent dtc) {
		if (!isShowingUndefinedBytes()) {
			throw new UnsupportedOperationException();
		}
		if (!(viewComposite instanceof Structure struct)) {
			throw new UnsupportedOperationException();
		}
		if (struct.isPackingEnabled()) {
			throw new UnsupportedOperationException();
		}

		// TODO: May  need special logic if dtc is zero-length component
		int length = getLength();
		int nextCompOffset = dtc.getEndOffset() + 1;
		if (nextCompOffset >= length) {
			return 0;
		}
		DataTypeComponent nextDefinedDtc =
			struct.getDefinedComponentAtOrAfterOffset(nextCompOffset);
		int nextDefinedOffset = (nextDefinedDtc == null) ? length : nextDefinedDtc.getOffset();
		return Math.max(0, nextDefinedOffset - nextCompOffset); // prevent negative return value
	}

	/**
	 * Replaces the components of the original structure with those of the edited one.
	 * Transaction must already be started on the {@link #getOriginalDataTypeManager()
	 * original datatype manager}.
	 */
	protected abstract void replaceOriginalComponents();

	@Override
	protected void checkIsAllowableDataType(DataType dataType) throws InvalidDataTypeException {

		super.checkIsAllowableDataType(dataType);

		// Verify that we aren't adding this structure or anything that it is
		// part of to this editable structure.
		if (dataType.equals(viewComposite)) {
			String msg = "Data type \"" + dataType.getDisplayName() + "\" can't contain itself.";
			throw new InvalidDataTypeException(msg);
		}
		else if (DataTypeUtilities.isSecondPartOfFirst(dataType, viewComposite)) {
			String msg = "Data type \"" + dataType.getDisplayName() + "\" has \"" +
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
		return viewDTM.withTransaction("Shift Up", () -> {
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
		});
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
		return viewDTM.withTransaction("Shift Down", () -> {
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
		});
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
		int startIndex = range.getStart().getIndex().intValue();
		int endIndex = range.getEnd().getIndex().intValue() - 1;
		int numSelected = endIndex - startIndex + 1;
		boolean moved = false;
		int newIndex = startIndex - 1;
		moved = shiftComponentsUp(startIndex, endIndex);
		if (moved) {
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
			FieldSelection tmpFieldSelection = new FieldSelection();
			tmpFieldSelection.addRange(newIndex, newIndex + numSelected);
			setSelection(tmpFieldSelection);
		}
		return moved;
	}

	@Override
	public void duplicateMultiple(int rowIndex, int multiple, TaskMonitor monitor)
			throws UsrException {
		DataTypeComponent originalComp = getComponent(rowIndex);
		DataType dt = originalComp.getDataType();
		int dtLen = originalComp.getLength();

		insertComponentMultiple(rowIndex + 1, dt, dtLen, multiple, monitor);

		// Adjust the selection since we added some components. Select last component added.
		setSelection(new int[] { rowIndex + multiple });

		lastNumDuplicates = multiple;
	}

	@Override
	protected void createArray(int numElements) throws InvalidDataTypeException, UsrException {
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

		ArrayDataType array = new ArrayDataType(dt, numElements, comp.getLength(), viewDTM);
		viewDTM.withTransaction("Create Array", () -> {
			if (getNumSelectedComponentRows() > 1) {
				replaceComponentRange(rowIndex,
					selection.getFieldRange(0).getEnd().getIndex().intValue() - 1, array,
					array.getLength());
			}
			else {
				replace(rowIndex, array, array.getLength()); // Can throw UsrException.
			}
		});
		componentEdited();
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
	 * Cause the component at the specified index to consume undefined bytes
	 * that follow it.
	 * Note: this method adjusts the selection.
	 *
	 * @param rowIndex the row index
	 * @return the number of Undefined bytes consumed.
	 */
	protected int consumeByComponent(int rowIndex) {
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

	@Override
	public void setValueAt(Object aValue, int rowIndex, int modelColumnIndex) {
		try {
			settingValueAt = true;
			fieldEdited(aValue, rowIndex, modelColumnIndex);
		}
		finally {
			settingValueAt = false;
		}
	}

	@Override
	public void setComponentDataTypeInstance(int rowIndex, DataType dt, int length)
			throws UsrException {
		if (getComponent(rowIndex) == null) {
			// Replacing data type in unlocked mode replaces only
			// that data type and structure size may change.
			insert(rowIndex, dt, length);
		}
		else {
			// Replacing data type in unlocked mode replaces only
			// that data type and structure size may change.
			replace(rowIndex, dt, length);
		}
	}

	@Override
	public void validateComponentName(int rowIndex, String name) throws UsrException {
		if (nameExistsElsewhere(name, rowIndex)) {
			throw new InvalidNameException("Name \"" + name + "\" already exists.");
		}
	}

	@Override
	public boolean setComponentName(int rowIndex, String name) throws InvalidNameException {

		String oldName = getComponent(rowIndex).getFieldName();
		if (Objects.equals(oldName, name)) {
			return false;
		}

		if (nameExistsElsewhere(name, rowIndex)) {
			throw new InvalidNameException("Name \"" + name + "\" already exists.");
		}
		return viewDTM.withTransaction("Set Component Name", () -> {
			try {
				getComponent(rowIndex).setFieldName(name); // setFieldName handles trimming
				return true;
			}
			catch (DuplicateNameException exc) {
				throw new InvalidNameException(exc.getMessage());
			}
		});
	}

	@Override
	public boolean setComponentComment(int rowIndex, String comment) {

		String oldComment = getComponent(rowIndex).getComment();
		String newComment = comment;
		if (newComment.equals("")) {
			newComment = null;
		}

		if (Objects.equals(oldComment, newComment)) {
			return false;
		}

		viewDTM.withTransaction("Set Component Comment",
			() -> getComponent(rowIndex).setComment(comment));

		fireTableCellUpdated(rowIndex, getCommentColumn());
		componentDataChanged();
		return true;
	}

	/**
	 * Returns whether the selected component(s) can be moved up (to the next lower index).
	 */
	@Override
	public boolean isMoveUpAllowed() {
		if (!isContiguousSelection()) {
			return false;
		}
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

	@Override
	public void restored(DataTypeManager dataTypeManager) {

		if (originalDTM == null) {
			// editor unloaded
			return;
		}

		if (!originalCompositeExists()) {

			if (originalCompositeId != DataTypeManager.NULL_DATATYPE_ID && !hasChanges) {
				provider.dispose(); // Close editor
				return;
			}

			// NOTE: Removed types will remain if used directly by edited components.
			if (viewDTM.refreshDBTypesFromOriginal()) {
				setStatus("Dependency datatypes have changed or been removed");
			}

			if (originalCompositeId != DataTypeManager.NULL_DATATYPE_ID) {
				provider.show();
				// The user has modified the structure so prompt for whether or
				// not to close the structure.
				String question = "The " + getOriginType() + " \"" + originalDTM.getName() +
					"\" has changed and \n" + "\"" + currentName +
					"\" no longer exists outside the editor.\n" + "Discard edits and close the " +
					getTypeName() + " editor?";
				String title = "Close " + getTypeName() + " Editor?";
				int response = OptionDialog.showYesNoDialogWithNoAsDefaultButton(
					provider.getComponent(), title, question);
				if (response == OptionDialog.YES_OPTION) {
					provider.dispose(); // Close editor
					return;
				}

				reloadFromView();

				return;
			}

			fireTableDataChanged();
			componentDataChanged();
			return;
		}

		T composite = getOriginalComposite();
		boolean reload = true;
		if (hasChanges || !viewComposite.isEquivalent(composite)) {
			hasChanges = true;
			provider.show();
			// The user has modified the structure so prompt for whether or
			// not to reload the structure.
			String question = "The " + getOriginType() + " \"" + originalDTM.getName() +
				"\" has been restored.\n" + "\"" + currentName +
				"\" may have changed outside the editor.\n" + "Discard edits and reload the " +
				getTypeName() + "?";
			String title = "Reload " + getTypeName() + " Editor?";
			int response = OptionDialog
					.showYesNoDialogWithNoAsDefaultButton(provider.getComponent(), title, question);
			if (response != OptionDialog.YES_OPTION) {
				reload = false;
			}
		}
		if (reload) {
			load(composite); // reload the structure
			setStatus("Editor reloaded");
			return;
		}

		if (viewDTM.refreshDBTypesFromOriginal()) {
			setStatus("Dependency datatypes have changed or been removed");
		}
		fireTableDataChanged();
		componentDataChanged();
	}

//==================================================================================================
// Override CompositeViewerModel CategoryChangeListener methods
//==================================================================================================

	@Override
	public void dataTypeRemoved(DataTypeManager dtm, DataTypePath path) {

		if (dtm != originalDTM) {
			throw new AssertException("Listener only supports original DTM");
		}

		if (!isLoaded()) {
			return;
		}

		DataType dataType = viewDTM.getDataType(path);
		if (dataType == null) {
			return;
		}

		if (!path.equals(originalDataTypePath)) {
			if (!viewDTM.isViewDataTypeFromOriginalDTM(dataType)) {
				return;
			}
			if (hasSubDt(viewComposite, path)) {
				String msg = "Removed sub-component data type \"" + path;
				setStatus(msg, true);
			}
			viewDTM.withTransaction("Removed Dependency", () -> {
				viewDTM.clearUndoOnChange();
				viewDTM.remove(dataType, TaskMonitor.DUMMY);
			});
			fireTableDataChanged();
			componentDataChanged();
			return;
		}

		if (originalCompositeId == DataTypeManager.NULL_DATATYPE_ID) {
			return;
		}

		consideringReplacedDataType = true;
		try {
			provider.show();
			// The user has modified the structure so prompt for whether or
			// not to close the structure.
			String question =
				"The " + getOriginType() + " \"" + originalDTM.getName() + "\" has changed and \n" +
					"\"" + getCompositeName() + "\" no longer exists outside the editor.\n" +
					"Discard edits and close the " + getTypeName() + " editor?";
			String title = "Close " + getTypeName() + " Editor?";
			int response = OptionDialog
					.showYesNoDialogWithNoAsDefaultButton(provider.getComponent(), title, question);
			if (response == OptionDialog.YES_OPTION) {
				provider.closeComponent(true); // Close editor
				return;
			}

			reloadFromView();
		}
		finally {
			consideringReplacedDataType = false;
		}
	}

	@Override
	public void dataTypeRenamed(DataTypeManager dtm, DataTypePath oldPath, DataTypePath newPath) {
		dataTypeMoved(dtm, oldPath, newPath);
	}

	@Override
	public void dataTypeMoved(DataTypeManager dtm, DataTypePath oldPath, DataTypePath newPath) {

		if (dtm != originalDTM) {
			throw new AssertException("Listener only supports original DTM");
		}

		if (!isLoaded()) {
			return;
		}

		if (oldPath.equals(newPath)) {
			return;
		}

		String newName = newPath.getDataTypeName();
		String oldName = oldPath.getDataTypeName();

		CategoryPath newCategoryPath = newPath.getCategoryPath();
		CategoryPath oldCategoryPath = oldPath.getCategoryPath();

		// Does the old name match our original name.
		// Check originalCompositeId to ensure original type is managed
		if (originalCompositeId != DataTypeManager.NULL_DATATYPE_ID &&
			oldPath.equals(originalDataTypePath)) {

			viewDTM.withTransaction("Name Changed", () -> {
				viewDTM.clearUndoOnChange();
				originalDataTypePath = newPath;
				try {
					if (viewComposite.getName().equals(oldName)) {
						setName(newName);
					}
					if (!newCategoryPath.equals(oldCategoryPath)) {
						viewComposite.setCategoryPath(newCategoryPath);
					}
				}
				catch (InvalidNameException | DuplicateNameException e) {
					Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
				}
			});
			compositeInfoChanged();
		}
		else {
			// Check for managed datatype changing
			DataType originalDt = originalDTM.getDataType(newPath);
			if (!(originalDt instanceof DatabaseObject)) {
				return;
			}
			DataType dt = viewDTM.findMyDataTypeFromOriginalID(originalDTM.getID(originalDt));
			if (dt == null) {
				return;
			}
			viewDTM.withTransaction("Renamed Dependency", () -> {
				viewDTM.clearUndoOnChange();
				try {
					dt.setName(newName);
					if (!newCategoryPath.equals(oldCategoryPath)) {
						dt.setCategoryPath(newCategoryPath);
					}
				}
				catch (InvalidNameException | DuplicateNameException e) {
					Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
				}
			});
		}

		fireTableDataChanged();
		componentDataChanged();
	}

	@Override
	public void dataTypeChanged(DataTypeManager dtm, DataTypePath path) {
		try {

			if (dtm != originalDTM) {
				throw new AssertException("Listener only supports original DTM");
			}

			if (!isLoaded()) {
				return;
			}

			// If we don't currently have any modifications that need applying and
			// the structure in the editor just changed, then show the changed
			// structure.
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
					if (hasChanges) {
						provider.show();
						String message = "<html>" +
							HTMLUtilities.escapeHTML(originalDataTypePath.getDataTypeName()) +
							" has changed outside the editor.<br>" +
							"Discard edits and reload the " + getTypeName() + "?";
						String title = "Reload " + getTypeName() + " Editor?";
						int response = OptionDialog.showYesNoDialogWithNoAsDefaultButton(
							provider.getComponent(), title, message);
						if (response == OptionDialog.OPTION_ONE) {
							load(getOriginalComposite());
						}
					}
					else {
						Composite changedComposite = getOriginalComposite();
						if ((changedComposite != null) &&
							!viewComposite.isEquivalent(changedComposite)) {
							load(getOriginalComposite());
							setStatus(viewComposite.getPathName() + " changed outside the editor.",
								false);
						}
					}
				}
				finally {
					originalIsChanging = false;
				}
			}
			else {
				// NOTE: There is the risk of a cascade of change notifications resulting in multiple
				// undo transactions for the viewDTM.  An editor save could generate quite a few with
				// potentially many types getting changed by one change.
				DataType changedDt = originalDTM.getDataType(path);
				if (!(changedDt instanceof DatabaseObject)) {
					return;
				}
				DataType viewDt =
					viewDTM.findMyDataTypeFromOriginalID(originalDTM.getID(changedDt));
				if (viewDt == null) {
					return;
				}
				try {
					viewDTM.withTransaction("Changed " + path, () -> {
						viewDTM.clearUndoOnChange();
						viewDTM.replaceDataType(viewDt, changedDt, true);
					});
				}
				catch (DataTypeDependencyException e) {
					throw new AssertException(e);
				}

				// Clear undo/redo stack to avoid inconsistency with originalDTM
				viewDTM.clearUndo();

				fireTableDataChanged();
				componentDataChanged();
			}
		}
		catch (ConcurrentModificationException e) {
			// do nothing, the delete will fix things later
		}
	}

	@Override
	public void dataTypeReplaced(DataTypeManager dtm, DataTypePath oldPath, DataTypePath newPath,
			DataType newDataType) {

		if (dtm != originalDTM) {
			throw new AssertException("Listener only supports original DTM");
		}

		if (!isLoaded()) {
			return;
		}

		if (!oldPath.equals(originalDataTypePath)) {
			// Check for type which may be referenced by viewComposite
			DataType dt = viewDTM.getDataType(oldPath);
			if (dt == null || !viewDTM.isViewDataTypeFromOriginalDTM(dt)) {
				return;
			}

			if (hasSubDt(viewComposite, oldPath)) {
				String msg = "Replaced data type \"" + oldPath +
					"\", which is a sub-component of \"" + getOriginalDataTypeName() + "\".";
				setStatus(msg, true);
			}
			// NOTE: depending upon event sequence and handling a
			// re-load may have occurred and replacement may be unnecessary
			try {
				viewDTM.withTransaction("Replaced Dependency", () -> {
					viewDTM.clearUndoOnChange();
					viewDTM.replaceDataType(dt, newDataType, true);
				});
			}
			catch (DataTypeDependencyException e) {
				throw new AssertException(e);
			}

			// Clear undo/redo stack to avoid inconsistency with originalDTM
			viewDTM.clearUndo();

			fireTableDataChanged();
			componentDataChanged();
			return;
		}

		consideringReplacedDataType = true;
		try {
			provider.show();

			if (hasChanges) {
				String message = "<html>" + HTMLUtilities.escapeHTML(oldPath.getPath()) +
					" has been replaced outside the editor.<br>" +
					"Discard edits and close?</html>";
				String title = "Close " + getTypeName() + " Editor?";
				int response = OptionDialog.showYesNoDialogWithNoAsDefaultButton(
					provider.getComponent(), title, message);
				if (response != OptionDialog.OPTION_ONE) {
					compositeInfoChanged();
					return;
				}
			}
			else {
				String message = "<html>" + HTMLUtilities.escapeHTML(oldPath.getPath()) +
					" has been replaced outside the editor.</html>";
				Msg.showWarn(this, provider.getComponent(), "Closing " + getTypeName() + " Editor",
					message);
			}

			// fast close, discard any changes
			provider.closeComponent(true);
		}
		finally {
			consideringReplacedDataType = false;
		}
	}

//==================================================================================================
// End of Override CompositeViewerModel CategoryChangeListener methods
//==================================================================================================

	@Override
	public void fireTableDataChanged() {

		updatingSelection(() -> {
			super.fireTableDataChanged(); // This causes the table selection to go away.
			selectionChanged(); // This sets the selection back.
		});
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
		DataTypeComponent dtc = getComponent(rowIndex);
		DataType dt = dtc.getDataType();
		int dtcLen = dtc.getLength();

		int maxDups = (Integer.MAX_VALUE - getLength());
		if (dtcLen > 0) {
			maxDups /= dtcLen;
			if (dt != DataType.DEFAULT && isShowingUndefinedBytes() && !isAtEnd(rowIndex)) {
				// If editModel is showing undefined bytes (non-packed)
				// then constrain by number of undefined bytes that follow.
				maxDups = getNumUndefinedBytesAfter(dtc) / dtcLen;
			}
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
			return getMaxDuplicates(rowIndex) + 1;
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

	protected int convertRowToOrdinal(int rowIndex) {
		return rowIndex;
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
			hasChanges = false;
			return hasChanges;
		}

		PackingType packingType = getPackingType();
		AlignmentType alignmentType = getAlignmentType();

		hasChanges = (packingType != oldComposite.getPackingType()) ||
			(alignmentType != oldComposite.getAlignmentType()) ||
			(packingType == PackingType.EXPLICIT &&
				getExplicitPackingValue() != oldComposite.getExplicitPackingValue()) ||
			(alignmentType == AlignmentType.EXPLICIT &&
				getExplicitMinimumAlignment() != oldComposite.getExplicitMinimumAlignment());
		return hasChanges;
	}

	/**
	 * Return the (minimum) alignment type for the structure or union being viewed
	 * @return the alignment type
	 */
	public AlignmentType getAlignmentType() {
		return viewComposite.getAlignmentType();
	}

	public int getExplicitMinimumAlignment() {
		return viewComposite.getExplicitMinimumAlignment();
	}

	public void setAlignmentType(AlignmentType alignmentType, int explicitValue) {
		viewDTM.withTransaction("Set Alignment", () -> {
			AlignmentType currentAlignType = getAlignmentType();
			if (alignmentType == AlignmentType.DEFAULT) {
				if (currentAlignType == AlignmentType.DEFAULT) {
					return;
				}
				viewComposite.setToDefaultAligned();
			}
			else if (alignmentType == AlignmentType.MACHINE) {
				if (currentAlignType == AlignmentType.MACHINE) {
					return;
				}
				viewComposite.setToMachineAligned();
			}
			else {
				if (currentAlignType == AlignmentType.EXPLICIT &&
					explicitValue == viewComposite.getExplicitMinimumAlignment()) {
					return;
				}
				viewComposite.setExplicitMinimumAlignment(explicitValue);
			}
		});
		if (fixSelection()) {
			selectionChanged();
		}
		notifyCompositeChanged();
	}

	public boolean isPackingEnabled() {
		return viewComposite.isPackingEnabled();
	}

	public PackingType getPackingType() {
		return viewComposite.getPackingType();
	}

	public int getExplicitPackingValue() {
		return viewComposite.getExplicitPackingValue();
	}

	public void setPackingType(PackingType packingType, int explicitValue) {
		viewDTM.withTransaction("Set Packing", () -> {
			PackingType currentPacktype = getPackingType();
			if (packingType == PackingType.DISABLED) {
				if (currentPacktype == PackingType.DISABLED) {
					return;
				}
				viewComposite.setPackingEnabled(false);
			}
			else if (packingType == PackingType.DEFAULT) {
				if (currentPacktype == PackingType.DEFAULT) {
					return;
				}
				viewComposite.setToDefaultPacking();
			}
			else {
				if (currentPacktype == PackingType.EXPLICIT &&
					explicitValue == viewComposite.getExplicitPackingValue()) {
					return;
				}
				viewComposite.setExplicitPackingValue(explicitValue);
			}
		});
		if (fixSelection()) {
			selectionChanged();
		}
		notifyCompositeChanged();
	}

	public int getActualAlignment() {
		return viewComposite.getAlignment();
	}

}
