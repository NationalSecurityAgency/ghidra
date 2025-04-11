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

import docking.widgets.dialogs.NumberInputDialog;
import docking.widgets.fieldpanel.support.FieldRange;
import docking.widgets.fieldpanel.support.FieldSelection;

/**
 * Composite editor model for maintaining information about the edits to
 * a composite data type. Updates the composite data type with the edit changes.
 * It also notifies any registered CompositeEditorModelListener listeners when
 * the composite data type is changed in the editor.
 * <P>This model provides methods for editing the composite data type and managing how
 * the changes occur.
 */

import ghidra.app.plugin.core.datamgr.util.DataTypeUtils;
import ghidra.app.util.datatype.EmptyCompositeException;
import ghidra.docking.settings.Settings;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.util.HelpLocation;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Model for editing a composite data type. Specific composite data type editors
 * should extend this class.
 * 
 * @param <T> Specific {@link Composite} type being managed
 */
abstract public class CompositeEditorModel<T extends Composite> extends CompositeViewerModel<T> {

	// TODO: This class should be combined with CompositeViewerModel since we only support editor use

	/**
	 * Whether or not an apply is occurring. Need to ignore changes to the
	 * original structure, if apply is causing them.
	 */
	protected boolean applyingFieldEdit = false;
	protected boolean stillBeginningEdit = false;

	protected boolean validName = true;
	protected String currentName = "";
	protected boolean editingField = false;
	protected boolean settingValueAt = false;

	protected int lastNumDuplicates = 1;
	protected int lastNumElements = 1;
	protected int lastNumBytes = 1;

	protected boolean hasChanges = false;
	protected boolean originalIsChanging = false;

	protected ArrayList<CompositeEditorModelListener> listeners = new ArrayList<>(1);

	/**
	 * Construct abstract composite editor model
	 * @param provider composite editor provider
	 */
	protected CompositeEditorModel(
			CompositeEditorProvider<T, ? extends CompositeEditorModel<T>> provider) {
		super(provider);
	}

	/**
	 * Reload from view composite and retain current edit state
	 */
	void reloadFromView() {

		if (!isLoaded()) {
			throw new AssertException();
		}

		if (isEditingField()) {
			endFieldEditing();
		}

		CompositeViewerDataTypeManager<T> oldViewDTM = viewDTM;

		originalComposite = viewDTM.getResolvedViewComposite();
		originalCompositeId = DataTypeManager.NULL_DATATYPE_ID;
		originalDataTypePath = originalComposite.getDataTypePath();
		currentName = originalComposite.getName();

		// Use temporary standalone view datatype manager
		viewDTM = new CompositeViewerDataTypeManager<>(viewDTM.getName(),
			viewDTM.getResolvedViewComposite(), this::componentEdited, this::restoreEditor);

		viewComposite = viewDTM.getResolvedViewComposite();

		// Clone all settings some of which do not get resolved.

		// NOTE: It is important to note that the editor will allow modification of component
		// default settings, however the underlying datatype default settings may not get copied
		// as they get resolved into the view datatype manager.  This may result in the incorrect
		// underlying datatype default setting value being presented when adjusting component
		// default settings.
		viewDTM.withTransaction("Load Settings",
			() -> cloneAllComponentSettings(originalComposite, viewComposite));
		viewDTM.clearUndo();

		// Dispose previous view DTM
		oldViewDTM.close();

		hasChanges = false;

		clearStatus();
		compositeInfoChanged();
		fireTableDataChanged();
		componentDataChanged();

		editorStateChanged(CompositeEditorModelListener.COMPOSITE_LOADED);
	}

	@Override
	public void load(T dataType) {
		Objects.requireNonNull(dataType);

		DataTypeManager dtm = dataType.getDataTypeManager();
		if (dtm == null) {
			throw new IllegalArgumentException(
				"Datatype " + dataType.getName() + " doesn't have a data type manager specified.");
		}

		long lastCompositeId = originalCompositeId;

		if (isEditingField()) {
			endFieldEditing();
		}

		if (isLoaded()) {
			unload();
		}

		// DataType should be a Composite.
		originalDTM = dtm;
		originalCompositeId = originalDTM.getID(dataType);
		originalComposite = dataType;
		originalDataTypePath = originalComposite.getDataTypePath();
		currentName = dataType.getName();

		createViewCompositeFromOriginalComposite();

		// Listen so we can update editor if name changes for this structure.
		originalDTM.addDataTypeManagerListener(this);

		hasChanges = false;

		if (originalCompositeId == DataTypeManager.NULL_DATATYPE_ID ||
			lastCompositeId != originalCompositeId) {
			// only clear the selection if loading a new type
			setSelection(new FieldSelection());
		}

		clearStatus();
		compositeInfoChanged();
		fireTableDataChanged();
		componentDataChanged();

		editorStateChanged(CompositeEditorModelListener.COMPOSITE_LOADED);
	}

	protected void restoreEditor() {
		if (isEditingField()) {
			endFieldEditing();
		}

		currentName = viewComposite.getName();
		updateAndCheckChangeState();

		compositeInfoChanged();
		fireTableDataChanged();
		componentDataChanged();
	}

	protected void componentEdited() {

		// NOTE: This method relies heavily on the viewDTM with transaction support
		// and this method specified as the changeCallback method.  If viewDTM has been
		// instantiated with a single open transaction this method will never be used
		// and provisions must be made for proper notification when changes are made.

		updateAndCheckChangeState(); // Update the composite's change state information.
		fireTableDataChanged();
		componentDataChanged();
	}

	/**
	 * Create {@code viewComposite} and {@link CompositeViewerDataTypeManager viewDTM} for this
	 * editor and the {@code originalComposite}.
	 */
	protected void createViewCompositeFromOriginalComposite() {

		if (viewDTM != null) {
			viewDTM.close();
			viewDTM = null;
		}

		// Use temporary standalone view datatype manager
		viewDTM =
			new CompositeViewerDataTypeManager<>(originalComposite.getDataTypeManager().getName(),
				originalComposite, this::componentEdited, this::restoreEditor);

		viewComposite = viewDTM.getResolvedViewComposite();

		// Clone all settings some of which do not get resolved.

		// NOTE: It is important to note that the editor will allow modification of component
		// default settings, however the underlying datatype default settings may not get copied
		// as they get resolved into the view datatype manager.  This may result in the incorrect
		// underlying datatype default setting value being presented when adjusting component
		// default settings.
		viewDTM.withTransaction("Load Settings",
			() -> cloneAllComponentSettings(originalComposite, viewComposite));
		viewDTM.clearUndo();
	}

	String getOriginType() {
		if (originalDTM instanceof ProgramBasedDataTypeManager) {
			return "Program";
		}
		return "Archive";
	}

	/**
	 * Called when the model is no longer needed.
	 * This is where all cleanup code for the model should be placed.
	 */
	@Override
	protected void dispose() {
		super.dispose();
	}

	/**
	 * Returns the docking windows component provider associated with this edit model.
	 * @return the component provider
	 */
	protected CompositeEditorProvider<T, ?> getProvider() {
		return provider;
	}

	/**
	 * Adds a CompositeEditorModelListener to be notified when changes occur.
	 * @param listener the listener to add.
	 */
	public void addCompositeEditorModelListener(CompositeEditorModelListener listener) {
		listeners.add(listener);
		super.addCompositeViewerModelListener(listener);
	}

	/**
	 * Removes a CompositeEditorModelListener that was being notified when changes occur.
	 * @param listener the listener to remove.
	 */
	public void removeCompositeEditorModelListener(CompositeEditorModelListener listener) {
		listeners.remove(listener);
		super.removeCompositeViewerModelListener(listener);
	}

	/**
	 * Gets the data type of the appropriate size to be placed at the indicated component index
	 *
	 * @param rowIndex index of the row (component)
	 * @param dt the data type to be placed at the row index
	 * @return a new data type instance
	 * @throws InvalidDataTypeException if the resulting data type is not allowed to be
	 * added at the indicated index
	 * @throws CancelledException if cancelled
	 */
	protected DataTypeInstance getDropDataType(int rowIndex, DataType dt)
			throws InvalidDataTypeException, CancelledException {

		FieldRange range = getSelectedRangeContaining(rowIndex);
		// Is the index in a selection.
		if (range != null) {
			// Set the index to the minimum index in this range.
			rowIndex = range.getStart().getIndex().intValue();
		}

		DataType currentDt = null;
		DataTypeComponent dtc = getComponent(rowIndex);
		if (dtc != null) {
			currentDt = dtc.getDataType();
		}
		if (!(currentDt instanceof Pointer)) {
			// stacking on pointer allows any data type
			checkIsAllowableDataType(dt);
		}

		DataType resultDt = DataUtilities.reconcileAppliedDataType(currentDt, dt, true);
		int resultLen = resultDt.getLength();

		if (resultDt instanceof Dynamic) {
			resultLen = DataTypeHelper.requestDtSize(getProvider(), resultDt.getDisplayName(),
				lastNumBytes, getMaxAddLength(rowIndex));
		}
		else if (resultLen == 0) {
			throw new InvalidDataTypeException("Data types of size 0 are not allowed.");
		}

		return DataTypeInstance.getDataTypeInstance(resultDt, resultLen,
			viewComposite.isPackingEnabled());
	}

	/**
	 *  This updates one of the values for a component that is a field of
	 *  this data structure.
	 *  @param aValue the new value for the field
	 * @param rowIndex the index of the row in the component table.
	 *  @param modelColumnIndex the model field index within the component
	 */
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

	/**
	 * Gets called to update/validate the current editable location in the table.
	 * @param value the new cell value
	 * @param rowIndex the index of the row in the component table.
	 * @param columnIndex the column index for the table cell in the
	 * current model.
	 * @return true if the field was updated or validated successfully.
	 */
	protected boolean fieldEdited(Object value, int rowIndex, int columnIndex) {
		if (applyingFieldEdit) {
			return true; // the one in progress will indicate any errors.
		}
		try {
			applyingFieldEdit = true;
			if (columnIndex == getDataTypeColumn()) {
				return setComponentDataType(rowIndex, value);
			}
			else if (columnIndex == getNameColumn()) {
				return setComponentName(rowIndex, ((String) value).trim());
			}
			else if (columnIndex == getCommentColumn()) {
				return setComponentComment(rowIndex, (String) value);
			}
			return false;
		}
		catch (UsrException e) {
			setStatus(e.getMessage());
			return false;
		}
		finally {
			updateAndCheckChangeState();
			applyingFieldEdit = false;
		}
	}

//==================================================================================================
// METHODS FOR CHANGING THE COMPOSITE
//==================================================================================================

	/**
	 * Called whenever the edit state of the data structure changes.
	 *
	 * @param type the type of state change: COMPOSITE_MODIFIED, COMPOSITE_UNMODIFIED,
	 * COMPOSITE_LOADED, NO_COMPOSITE_LOADED.
	 */
	protected void editorStateChanged(int type) {
		for (CompositeEditorModelListener listener : listeners) {
			listener.compositeEditStateChanged(type);
		}
		this.fireTableDataChanged();
	}

	/**
	 *  Sets the name for the composite data type being edited.
	 *
	 * @param name the new name.
	 * 
	 * @throws DuplicateNameException if the name already exists.
	 * @throws InvalidNameException if the name is invalid
	 */
	public void setName(String name) throws DuplicateNameException, InvalidNameException {
		if (name.equals(currentName)) {
			return;
		}
		currentName = name;

		if (viewComposite != null) {
			validName = false;
			int txId = viewDTM.startTransaction("Set Name");
			try {
				viewComposite.setName(name);
			}
			finally {
				viewDTM.endTransaction(txId, true);
			}
			checkName(name);
			validName = true;
		}

		boolean nameModified = !currentName.equals(getOriginalDataTypeName());
		updateAndCheckChangeState();

		// Notify any listeners that the name modification state has changed.
		int type = (nameModified) ? CompositeEditorModelListener.COMPOSITE_MODIFIED
				: CompositeEditorModelListener.COMPOSITE_UNMODIFIED;
		editorStateChanged(type);
	}

	/**
	 *  Return the currently specified data type name of the composite being viewed.
	 */
	@Override
	public String getCompositeName() {
		return currentName;
	}

	/**
	 *  Sets the description for the composite data type being edited.
	 *
	 * @param desc the new description.
	 */
	protected void setDescription(String desc) {

		if (viewComposite != null) {
			if (!desc.equals(viewComposite.getDescription())) {
				viewDTM.withTransaction("Set Description",
					() -> viewComposite.setDescription(desc));
			}
		}

		updateAndCheckChangeState();

		// Notify any listeners that the name modification state has changed.
		Composite original = this.getOriginalComposite();
		boolean descriptionModified = (original != null) && !desc.equals(original.getDescription());
		int type = (descriptionModified) ? CompositeEditorModelListener.COMPOSITE_MODIFIED
				: CompositeEditorModelListener.COMPOSITE_UNMODIFIED;
		editorStateChanged(type);
	}

	/**
	 * Sets the data type for the component at the indicated rowIndex.
	 * @param rowIndex the row index of the component
	 * @param dataTypeObject a String or a DataType
	 * @return true if changed
	 * @throws UsrException if the type cannot be used
	 */
	protected boolean setComponentDataType(int rowIndex, Object dataTypeObject)
			throws UsrException {

		boolean success = viewDTM.withTransaction("Set Datatype", () -> {
			DataType previousDt = null;
			int previousLength = 0;
			String dtName = "";
			DataTypeComponent element = getComponent(rowIndex);
			if (element != null) {
				previousDt = element.getDataType();
				previousLength = element.getLength();
				dtName = previousDt.getDisplayName();
			}
			DataType newDt = null;
			int newLength;
			if (dataTypeObject instanceof DataTypeInstance dti) {
				newDt = dti.getDataType();
				newLength = dti.getLength();
			}
			else if (dataTypeObject instanceof DataType dt) {
				newDt = dt;
				newLength = newDt.getLength();
			}
			else if (dataTypeObject instanceof String dtString) {
				if (dtString.equals(dtName)) {
					return false;
				}
				newDt = DataTypeHelper.parseDataType(rowIndex, dtString, this, originalDTM,
					provider.dtmService);
				newLength = newDt.getLength();
			}
			if (newDt == null) {
				return false; // Was nothing and is nothing.
			}

			if (DataTypeComponent.usesZeroLengthComponent(newDt)) {
				newLength = 0;
			}

			DataType dataType = newDt.clone(originalDTM);
			newLength = newDt.getLength();

			checkIsAllowableDataType(newDt);

			if (newLength < 0) {
				// prefer previous size first
				int suggestedLength = (previousLength <= 0) ? lastNumBytes : previousLength;
				DataTypeInstance sizedDataType = DataTypeHelper.getSizedDataType(provider, newDt,
					suggestedLength, getMaxReplaceLength(rowIndex));
				if (sizedDataType == null) {
					return false;
				}
				newLength = sizedDataType.getLength();
				if (newLength <= 0) {
					throw new UsrException("Can't currently add this data type.");
				}
				newDt = sizedDataType.getDataType();
			}

			if ((previousDt != null) && newDt.isEquivalent(previousDt) &&
				newLength == previousLength) {
				return false;
			}

			int maxLength = getMaxReplaceLength(rowIndex);
			if (maxLength > 0 && newLength > maxLength) {
				throw new UsrException(newDt.getDisplayName() + " doesn't fit within " + maxLength +
					" bytes, need " + newLength + " bytes");
			}

			// Set component datatype and length on view composite
			setComponentDataTypeInstance(rowIndex, newDt, newLength);
			return true;
		});

		if (success) {
			notifyCompositeChanged();
		}
		return success;
	}

	/**
	 * Sets the data type for the component at the indicated row index with an open
	 * transaction.
	 * @param rowIndex the row index of the component
	 * @param dt component datatype
	 * @param length component length
	 * @throws UsrException if invalid datatype or length specified
	 */
	abstract protected void setComponentDataTypeInstance(int rowIndex, DataType dt, int length)
			throws UsrException;

	/**
	 * Sets the data type for the component at the indicated index.
	 * @param rowIndex the row index of the component
	 * @param name the name
	 * @return true if a change was made
	 * @throws InvalidNameException if the name is invalid
	 */
	abstract public boolean setComponentName(int rowIndex, String name) throws InvalidNameException;

	/**
	 * Sets the data type for the component at the indicated index.
	 * @param rowIndex the row index of the component
	 * @param comment the comment
	 * @return true if a change was made
	 */
	abstract public boolean setComponentComment(int rowIndex, String comment);

	/**
	 * Clears the a defined components at the specified row. Clearing a component within a 
	 * non-packed structure causes a defined component to be replaced with a number of 
	 * undefined components. This may not the case when clearing a zero-length component or 
	 * bit-field which may not result in such undefined components. In the case of a 
	 * packed structure clearing is always completed without backfill.
	 * @param rowIndex the composite row to be cleared
	 */
	protected void clearComponent(int rowIndex) {
		clearComponents(new int[] { rowIndex });
	}

	/**
	 * Clears the all defined components at the specified rows. Clearing a component within a 
	 * non-packed structure causes a defined component to be replaced with a number of 
	 * undefined components. This may not the case when clearing a zero-length component or 
	 * bit-field which may not result in such undefined components. In the case of a 
	 * packed structure clearing is always completed without backfill.
	 * @param rows composite rows to be cleared
	 */
	abstract protected void clearComponents(int[] rows);

	/**
	 * Deletes all components at the specified rows.
	 * @param rows composite rows to be deleted.
	 */
	protected void deleteComponents(int[] rows) {
		for (int i = rows.length - 1; i >= 0; i--) {
			deleteComponent(rows[i]);
		}
		notifyCompositeChanged();
	}

	/**
	 * Deletes the component at the given rowIndex.
	 * @param rowIndex the row of the component to be deleted.
	 */
	abstract protected void deleteComponent(int rowIndex);

	/**
	 * Gets the maximum number of bytes available for a data type that is added at the indicated
	 * index. This can vary based on whether or not it is in a selection.
	 *
	 * @param rowIndex index of the row in the editor's composite data type.
	 * @return the length
	 */
	abstract protected int getMaxAddLength(int rowIndex);

	abstract public DataTypeComponent add(DataType dataType) throws UsrException;

	abstract protected DataTypeComponent add(int rowIndex, DataType dataType) throws UsrException;

	abstract protected DataTypeComponent add(int rowIndex, DataType dt, int dtLength)
			throws UsrException;

	abstract protected DataTypeComponent insert(DataType dataType) throws UsrException;

	abstract protected DataTypeComponent insert(int rowIndex, DataType dataType)
			throws UsrException;

	abstract protected DataTypeComponent insert(int rowIndex, DataType dt, int dtLength)
			throws UsrException;

	/**
	 * Gets the maximum number of bytes available for a new data type that
	 * will replace the current data type at the indicated component index.
	 * If there isn't a component with the indicated index, the max length
	 * will be determined by the lock mode.
	 *
	 * @param rowIndex index of the row for the component to replace.
	 * @return the maximum number of bytes that can be replaced.
	 */
	abstract protected int getMaxReplaceLength(int rowIndex);

	/**
	 * Update the datatype for the component located at the specified rowIndex.
	 * @param rowIndex the index of the row for the component to be updated
	 * @param dt new datatype to be applied
	 * @param dtLength datatype instance length
	 * @return updated component
	 * @throws UsrException if invalid parameters are provided
	 */
	abstract protected DataTypeComponent replace(int rowIndex, DataType dt, int dtLength)
			throws UsrException;

	/**
	 * Determine the maximum number of duplicates that can be created for
	 * the component at the indicated index. The duplicates would follow
	 * the component. The number allowed depends on how many fit based on
	 * the current lock/unlock state of the editor.
	 * <br>Note: This method doesn't care whether there is a selection or not.
	 *
	 * @param rowIndex the index of the row for the component to be duplicated.
	 * @return the maximum number of duplicates.
	 */
	abstract protected int getMaxDuplicates(int rowIndex);

	/**
	 * Creates multiple duplicates of the indicated component.
	 * The duplicates will be created at the index immediately after the
	 * indicated component.
	 * @param rowIndex the index of the row whose component is to be duplicated.
	 * @param multiple the number of duplicates to create.
	 * @param monitor the task monitor
	 * @throws UsrException if component can't be duplicated the indicated number of times.
	 */
	abstract protected void duplicateMultiple(int rowIndex, int multiple, TaskMonitor monitor)
			throws UsrException;

	/**
	 * Apply the changes for the current edited composite back to the
	 * original composite.
	 *
	 * @return true if apply succeeds
	 * @throws EmptyCompositeException if the structure doesn't have any components.
	 * @throws InvalidDataTypeException if this structure has a component that it is part of.
	 */
	abstract public boolean apply() throws EmptyCompositeException, InvalidDataTypeException;

	/**
	 * Determine the maximum number of array elements that can be created for
	 * the current selection. The array data type is assumed to become the
	 * data type of the first component in the selection. The current selection
	 * must be contiguous or 0 is returned.
	 *
	 * @return the number of array elements that fit in the current selection.
	 */
	abstract protected int getMaxElements();

	/**
	 *  Clear the selected components.
	 *
	 * @throws UsrException if the data type isn't allowed to be cleared.
	 */
	protected void createArray() throws UsrException {
		if (!isArrayAllowed()) {
			throw new UsrException("Array not permitted in current context");
		}
		int min = allowsZeroLengthComponents() ? 0 : 1;
		int max = getMaxElements();
		if (isSingleRowSelection()) {
			if (max != 0) {
				int initial = getLastNumElements();
				NumberInputDialog numberInputDialog =
					new NumberInputDialog("elements", ((initial > 0) ? initial : 1), min, max);
				String helpAnchor = provider.getHelpName() + "_" + "Elements_NumberInputDialog";
				HelpLocation helpLoc = new HelpLocation(provider.getHelpTopic(), helpAnchor);
				numberInputDialog.setHelpLocation(helpLoc);
				if (numberInputDialog.show()) {
					int numOfElements = numberInputDialog.getValue();
					try {
						createArray(numOfElements);
					}
					catch (Exception e1) {
						setStatus(e1.getMessage(), true);
					}
				}
			}
		}
		else if (isContiguousComponentSelection()) {
			// Multi-row selection uses selection size for array
			if (max > 1) {
				try {
					createArray(max);
				}
				catch (Exception e1) {
					setStatus(e1.getMessage(), true);
				}
			}
		}
	}

	protected void createArray(int numElements) throws InvalidDataTypeException, UsrException {
		if (selection.getNumRanges() != 1) {
			throw new UsrException("Can only create arrays on a contiguous selection.");
		}
		int currentIndex = selection.getFieldRange(0).getStart().getIndex().intValue();
		if (currentIndex >= getNumComponents()) {
			throw new UsrException("A component must be selected.");
		}
		if (isEditingField()) {
			endFieldEditing();
		}
		// Get data type to make into array.
		DataTypeComponent comp = getComponent(currentIndex);

		DataType dt = comp.getDataType();
		int len = dt.getLength() > 0 ? dt.getLength() : comp.getLength();

		ArrayDataType array = new ArrayDataType(dt, numElements, len, viewDTM);
		replace(currentIndex, array, array.getLength());
	}

	/**
	 *  Clear the selected components.
	 *
	 * @throws UsrException if the data type isn't allowed to be cleared.
	 */
	public void clearSelectedComponents() throws UsrException {
		if (!isClearAllowed()) {
			throw new UsrException("Clearing is not allowed.");
		}
		if (isEditingField()) {
			endFieldEditing();
		}
		clearComponents(getSelectedComponentRows());
	}

	/**
	 *  Delete the selected components.
	 *
	 * @throws UsrException if the data type isn't allowed to be deleted.
	 */
	protected void deleteSelectedComponents() throws UsrException {
		if (!isDeleteAllowed()) {
			throw new UsrException("Deleting is not allowed.");
		}
		if (isEditingField()) {
			endFieldEditing();
		}
		deleteComponents(getSelectedComponentRows());
		selection.clear();
	}

	public boolean isValidName() {
		return validName;
	}

	/**
	 * Returns whether or not the editor has changes that haven't been applied.
	 * Changes can also mean a new data type that hasn't yet been saved.
	 * @return if there are changes
	 */
	public boolean hasChanges() {
		return hasChanges;
	}

	public boolean updateAndCheckChangeState() {
		if (originalIsChanging) {
			return false;
		}
		Composite oldComposite = getOriginalComposite();
		String oldName = getOriginalDataTypeName();
		String oldDesc = oldComposite != null ? oldComposite.getDescription() : "";
		if (oldDesc == null) {
			oldDesc = "";
		}
		int oldSize = oldComposite != null ? oldComposite.getLength() : 0;

		String newDesc = viewComposite.getDescription();
		if (newDesc == null) {
			newDesc = "";
		}
		int newSize = viewComposite.getLength();

		hasChanges = !currentName.equals(oldName) || !newDesc.equals(oldDesc) || oldSize != newSize;
		if (hasChanges) {
			return true;
		}

		boolean noCompChanges = false;
		if (oldComposite != null && !hasChanges) {
			noCompChanges = (viewComposite.isEquivalent(oldComposite) &&
				hasSameComponentSettings(viewComposite, oldComposite) &&
				!hasCompPathNameChanges(viewComposite, oldComposite));
		}
		else {
			noCompChanges = getNumComponents() == 0;
		}
		hasChanges = !noCompChanges;
		return hasChanges;
	}

	private boolean hasSameComponentSettings(Composite currentViewComposite,
			Composite oldComposite) {
		DataTypeComponent[] viewComps = currentViewComposite.getDefinedComponents();
		DataTypeComponent[] oldComps = oldComposite.getDefinedComponents();
		if (viewComps.length != oldComps.length) {
			return false;
		}
		for (int i = 0; i < viewComps.length; i++) {
			if (!hasSameSettings(viewComps[i], oldComps[i])) {
				return false;
			}
		}
		return true;
	}

	private boolean hasSameSettings(DataTypeComponent viewDtc, DataTypeComponent oldDtc) {
		Settings viewDtcSettings = viewDtc.getDefaultSettings();
		Settings oldDtcSettings = oldDtc.getDefaultSettings();
		String[] viewSettingsNames = viewDtcSettings.getNames();
		String[] oldSettingsNames = oldDtcSettings.getNames();
		if (viewSettingsNames.length != oldSettingsNames.length) {
			return false;
		}
		Arrays.sort(viewSettingsNames);
		Arrays.sort(oldSettingsNames);
		if (!Arrays.equals(viewSettingsNames, oldSettingsNames)) {
			return false;
		}
		for (String name : viewSettingsNames) {
			if (!Objects.equals(viewDtcSettings.getValue(name), oldDtcSettings.getValue(name))) {
				return false;
			}
		}
		return true;
	}

	private void cloneAllComponentSettings(Composite sourceComposite, Composite destComposite) {
		DataTypeComponent[] sourceComps = sourceComposite.getDefinedComponents();
		DataTypeComponent[] destComps = destComposite.getDefinedComponents();
		assert (sourceComps.length == destComps.length);
		for (int i = 0; i < sourceComps.length; i++) {
			Settings sourceDtcSettings = sourceComps[i].getDefaultSettings();
			Settings destDtcSettings = destComps[i].getDefaultSettings();
			destDtcSettings.clearAllSettings();
			for (String name : sourceDtcSettings.getNames()) {
				destDtcSettings.setValue(name, sourceDtcSettings.getValue(name));
			}
		}
	}

	protected void updateOriginalComponentSettings(Composite sourceComposite,
			Composite destComposite) {
		DataTypeComponent[] sourceComps = sourceComposite.getDefinedComponents();
		DataTypeComponent[] destComps = destComposite.getDefinedComponents();
		assert (sourceComps.length == destComps.length);
		for (int i = 0; i < sourceComps.length; i++) {
			if (hasSameSettings(sourceComps[i], destComps[i])) {
				continue;
			}
			Settings sourceDtcSettings = sourceComps[i].getDefaultSettings();
			Settings destDtcSettings = destComps[i].getDefaultSettings();
			destDtcSettings.clearAllSettings();
			for (String name : sourceDtcSettings.getNames()) {
				destDtcSettings.setValue(name, sourceDtcSettings.getValue(name));
			}
		}
	}

	private boolean hasCompPathNameChanges(Composite currentViewComposite, Composite oldComposite) {
		// Check component data type pathnames.
		DataTypeComponent[] comps = currentViewComposite.getDefinedComponents();
		DataTypeComponent[] oldComps = oldComposite.getDefinedComponents();
		if (comps.length != oldComps.length) {
			return true;
		}
		for (int i = 0; i < comps.length; i++) {
			String dtPathName = comps[i].getDataType().getPathName();
			String oldDtPathName = oldComps[i].getDataType().getPathName();
			if (!dtPathName.equals(oldDtPathName)) {
				return true;
			}
		}
		return false;
	}

	protected void notifyCompositeChanged() {
		updateAndCheckChangeState();
		fireTableDataChanged();
		compositeInfoChanged();
		componentDataChanged();
	}

	@Override
	public void fireTableDataChanged() {
		swing(super::fireTableDataChanged);
	}

//==================================================================================================
// METHODS FOR THE FIELD EDITING
//==================================================================================================

	protected boolean beginEditingField(int modelRow, int modelColumn) {
		if (isEditingField()) {
			return false;
		}
		try {
			stillBeginningEdit = true; // We want to know we are still beginning an edit when we fix the selection.
			editingField = true;
			setLocation(modelRow, modelColumn);
			setSelection(new int[] { modelRow });
			notifyEditingChanged();
		}
		finally {
			stillBeginningEdit = false;
		}
		return true;
	}

	/**
	 * Change the edit state to indicate no longer editing a field.
	 * @return the edit state to indicate no longer editing a field.
	 */
	protected boolean endEditingField() {
		if (!isEditingField()) {
			return false;
		}
		editingField = false;
		notifyEditingChanged();
		return true;
	}

	/**
	 * Returns whether the user is currently editing a field's value.
	 * @return whether the user is currently editing a field's value.
	 */
	public boolean isEditingField() {
		return !settingValueAt && editingField;
	}

	/**
	 * Notification that a field edit has ended.
	 */
	protected void endFieldEditing() {
		if (!isEditingField()) {
			return;
		}
		for (CompositeEditorModelListener listener : listeners) {
			listener.endFieldEditing();
		}
	}

	/**
	 *  Returns whether or not the editor is showing undefined bytes.
	 *  @return true if the editor is showing undefined bytes.
	 */
	abstract protected boolean isShowingUndefinedBytes();

	private void notifyEditingChanged() {
		for (CompositeEditorModelListener listener : listeners) {
			listener.compositeEditStateChanged(
				isEditingField() ? CompositeEditorModelListener.EDIT_STARTED
						: CompositeEditorModelListener.EDIT_ENDED);
		}
	}

	public void cycleDataType(CycleGroup cycleGroup) {

		// Only cycle a single component selection.
		if (getNumSelectedRows() != 1) {
			setStatus("Can only cycle when a single row is selected.", true);
			return;
		}
		try {
			int currentIndex = getMinIndexSelected();
			DataType dt = getNextCycleDataType(cycleGroup);
			if (dt != null) {
				DataTypeInstance dti = DataTypeHelper.getFixedLength(this, currentIndex, dt,
					usesAlignedLengthComponents());
				if (dti == null) {
					return;
				}
				replace(currentIndex, dti.getDataType(), dti.getLength());
				// Set back to a single component selection so you can continue to cycle.
				setSelection(new int[] { currentIndex });
			}
			else {
				setStatus("No new data type in the cycle group fits.", true);
			}
		}
		catch (UsrException e1) {
			setStatus(e1.getMessage(), true);
		}
	}

	/**
	 * This gets the next data type in the cycle that fits in place of the
	 * currently selected component. If the currently selected component's data
	 * type is not in the cycle group, then the first data type that fits from
	 * the cycle group is returned. If no new data type from the cycle group
	 * fits at the selected component, null is returned.
	 *
	 * @param cycleGroup the cycle group of data types to choose from.
	 * @return the next data type or null
	 * @throws UsrException if more than 1 row is selected
	 */
	protected DataType getNextCycleDataType(CycleGroup cycleGroup) throws UsrException {

		if (getNumSelectedRows() != 1) {
			throw new UsrException("Single row selection needed to cycle data types.");
		}

		DataType startDataType = null;
		DataType dataType = null;
		int currentIndex = getMinIndexSelected();

		DataTypeComponent dtc = getComponent(currentIndex);
		if (dtc != null) {
			startDataType = dtc.getDataType();
			dataType = startDataType;
		}
		else {
			return cycleGroup.getNextDataType(null, true);
		}

		int cnt = cycleGroup.size();
		do {
			dataType = cycleGroup.getNextDataType(dataType, true);
			if (dataType == null || dataType.isEquivalent(startDataType)) {
				return null;
			}
			if (isReplaceAllowed(currentIndex, dataType)) {
				return dataType;
			}
		}
		while (--cnt > 0);

		return null;
	}

	/**
	 *  Check for any data member in the composite with the specified name
	 *  other than the component at the specified index.
	 *
	 * @param name the component name to look for.
	 * @param rowIndex index of the row (component).
	 *
	 * @return true if the name exists elsewhere.
	 */
	protected boolean nameExistsElsewhere(String name, int rowIndex) {
		if (name != null) {
			name = name.trim();
			if (name.length() == 0) {
				return false;
			}
			int numComponents = getNumComponents();
			for (int i = 0; i < rowIndex && i < numComponents; i++) {
				if (name.equals(getComponent(i).getFieldName())) {
					return true;
				}
			}
			for (int i = rowIndex + 1; i < numComponents; i++) {
				if (name.equals(getComponent(i).getFieldName())) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Determine if the data type is a valid one to place into the current structure being edited.
	 * If invalid, an exception will be thrown.
	 *
	 * @param datatype the data type
	 * @throws InvalidDataTypeException if the structure being edited is part
	 *         of the data type being inserted or doesn't have a valid size.
	 */
	protected void checkIsAllowableDataType(DataType datatype) throws InvalidDataTypeException {
		if (!allowsZeroLengthComponents() && DataTypeComponent.usesZeroLengthComponent(datatype)) {
			throw new InvalidDataTypeException(
				"Zero-length datatype not permitted: " + datatype.getName());
		}
		if (!allowsBitFields() && (datatype instanceof BitFieldDataType)) {
			throw new InvalidDataTypeException("Bitfield not permitted: " + datatype.getName());
		}
		if (datatype instanceof TypeDef) {
			datatype = ((TypeDef) datatype).getBaseDataType();
		}
		if (datatype instanceof FactoryDataType) {
			throw new InvalidDataTypeException(
				"Factory data types are not " + "allowed in a composite data type.");
		}
		else if (datatype instanceof Dynamic) {
			if (!((Dynamic) datatype).canSpecifyLength()) {
				throw new InvalidDataTypeException("Non-sizable Dynamic data types are not " +
					"allowed in a composite data type.");
			}
		}
	}

	protected boolean allowsZeroLengthComponents() {
		return true;
	}

	protected boolean allowsBitFields() {
		return true;
	}

	/**
	 * Returns whether or not addition of the specified component is allowed
	 * based on the current selection. The addition could be an insert or replace as
	 * determined by the state of the edit model.
	 *
	 * @param datatype the data type to be added.
	 * @return true if add allowed, else false
	 */
	abstract protected boolean isAddAllowed(DataType datatype);

	/**
	 * Returns whether or not addition of the specified component is allowed
	 * at the specified index. The addition could be an insert or replace as
	 * determined by the state of the edit model.
	 *
	 * @param rowIndex row index of the component in the composite data type.
	 * @param datatype the data type to be inserted.
	 * @return true if add allowed, else false
	 */
	abstract protected boolean isAddAllowed(int rowIndex, DataType datatype);

	/**
	 * Returns whether or not insertion of the specified data type is allowed
	 * at the specified index.
	 *
	 * @param rowIndex row index of the component in the composite data type.
	 * @param datatype the data type to be inserted.
	 * @return true if insert allowed, else false
	 */
	protected boolean isInsertAllowed(int rowIndex, DataType datatype) {
		return false;
	}

	/**
	 * Returns whether or not the selection is allowed to be changed into an array.
	 *  @return true if array conversion allowed, else false
	 */
	abstract protected boolean isArrayAllowed();

	/**
	 * Returns whether or not a bitfield is allowed at the current location.
	 *  @return true if add bitfield, else false
	 */
	abstract protected boolean isBitFieldAllowed();

	/**
	 * Returns whether or not clearing the selected components is allowed.
	 *  @return true if clear allowed, else false
	 */
	abstract protected boolean isClearAllowed();

	/**
	 * Returns whether or not the selected components can be deleted.
	 *  @return true if delete allowed, else false
	 */
	abstract protected boolean isDeleteAllowed();

	/**
	 * Returns whether or not the component at the selected index is allowed to be duplicated.
	 *  @return true if component duplication allowed, else false
	 */
	protected boolean isDuplicateAllowed() {
		return false;
	}

	/**
	 * Returns whether or not the base type of the component at the
	 * selected index is editable. If the base type is a composite
	 * then it is editable.
	 * Also, if there isn't a selection then it isn't allowed.
	 *  @return true if edit allowed, else false
	 */
	protected boolean isEditComponentAllowed() {
		if (this.getNumSelectedComponentRows() != 1) {
			return false;
		}
		int currentIndex = selection.getFieldRange(0).getStart().getIndex().intValue();
		DataTypeComponent comp = getComponent(currentIndex);
		DataType baseDt = null;
		if (comp != null) {
			baseDt = comp.getDataType();
			baseDt = DataTypeUtils.getBaseDataType(baseDt);
		}
		return ((baseDt != null) && !(baseDt instanceof BuiltInDataType) &&
			!(baseDt instanceof MissingBuiltInDataType) &&
			((baseDt instanceof Structure) || (baseDt instanceof Union) ||
				(baseDt instanceof Enum) || (baseDt instanceof FunctionDefinition)));
	}

	protected boolean isEditFieldAllowed() {
		return !isEditingField();
	}

	/**
	 * Returns whether the selected component(s) can be moved up (to the next lower index).
	 *  @return true if component move-up allowed, else false
	 */
	protected boolean isMoveUpAllowed() {
		return false;
	}

	/**
	 * Returns whether the selected component(s) can be moved down (to the next higher index).
	 *  @return true if component move-down allowed, else false
	 */
	protected boolean isMoveDownAllowed() {
		return false;
	}

	/**
	 * Moves a contiguous selection of components up by a single position. The component that was
	 * immediately above (at the index immediately preceding the selection) the selection will be
	 * moved below the selection (to what was the maximum selected component index).
	 * @return true if selected components were moved up.
	 * @throws UsrException if components can't be moved up.
	 */
	abstract protected boolean moveUp() throws UsrException;

	/**
	 * Moves a contiguous selection of components down by a single position. The component that was
	 * immediately below (at the index immediately following the selection) the selection will be
	 * moved above the selection (to what was the minimum selected component index).
	 * @return true if selected components were moved down.
	 * @throws UsrException if components can't be moved down.
	 */
	abstract protected boolean moveDown() throws UsrException;

	protected boolean isReplaceAllowed(int rowIndex, DataType dataType) {
		return false;
	}

	/**
	 * Returns whether the selected component can be unpackaged.
	 * @return whether the selected component can be unpackaged.
	 */
	protected boolean isUnpackageAllowed() {
		return false;
	}

	/**
	 * If the component at the indicated index is a composite data type,
	 * this gets the number of components that it contains.
	 *
	 * @param rowIndex the index of the component in the editor.
	 * @return the number of sub-components or 0.
	 */
	protected int getNumSubComponents(int rowIndex) {
		DataTypeComponent dtc = getComponent(rowIndex);
		if (dtc instanceof Composite) {
			Composite comp = (Composite) dtc;
			return comp.getNumComponents();
		}
		return 0;
	}

	/**
	 * Return the last number of bytes the user entered when prompted for
	 * a data type size.
	 * @return the number of bytes
	 */
	protected int getLastNumBytes() {
		return lastNumBytes;
	}

	/**
	 * Return the last number of duplicates the user entered when prompted for
	 * creating duplicates of a component.
	 * @return the number of duplicates
	 */
	protected int getLastNumDuplicates() {
		return lastNumDuplicates;
	}

	/**
	 * Return the last number of elements the user entered when prompted for
	 * creating an array.
	 * @return the number of elements
	 */
	protected int getLastNumElements() {
		return lastNumElements;
	}

	/**
	 * Sets the last number of bytes the user entered for a data type
	 * @param numBytes the last number of bytes entered
	 */
	protected void setLastNumBytes(int numBytes) {
		lastNumBytes = numBytes;
	}

	/**
	 * Sets the last number of bytes the user entered for a data type
	 * @param numDuplicates the last number of bytes entered
	 */
	protected void setLastNumDuplicates(int numDuplicates) {
		lastNumDuplicates = numDuplicates;
	}

	/**
	 * Sets the last number of bytes the user entered for a data type
	 * @param numElements the last number of bytes entered
	 */
	protected void setLastNumElements(int numElements) {
		lastNumElements = numElements;
	}

	/**
	 *  Saves the current selection in the structure components viewing area.
	 *
	 * @param rows the indices for the selected rows.
	 */
	@Override
	public void setSelection(int[] rows) {
		if (updatingSelection) {
			return;
		}
		FieldSelection tmpSelection = new FieldSelection();
		int numComponents = getNumComponents();
		for (int row2 : rows) {
			// Only add valid component rows (i.e. don't include blank last line)
			if (row2 < numComponents) {
				tmpSelection.addRange(row2, row2 + 1);
			}
		}
		if (this.selection.equals(tmpSelection)) {
			return;
		}

		// Normally if the user makes a new selection, we want to end any field editing
		// that is in progress, but if we are fixing up the selection during a beginEdit
		// then don't end field editing since we are in a transition state.
		if (!stillBeginningEdit) {
			endFieldEditing();
		}

		this.selection = tmpSelection;
		adjustCurrentRow();
		selectionChanged();
	}

	/**
	 * Sets the model's current selection to the indicated selection.
	 * If the selection is empty, it gets adjusted to the empty last line when in unlocked mode.
	 * @param selection the new selection
	 */
	@Override
	protected void setSelection(FieldSelection selection) {
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
		adjustCurrentRow();
		selectionChanged();
	}

	@SuppressWarnings("unused") // the exception is thrown by subclasses1
	protected void validateComponentOffset(int rowIndex, String offset) throws UsrException {
		// If the offset actually needs validating then override this method.
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
//	protected DataTypeInstance validateComponentDataType(int rowIndex, String dtString)
//			throws UsrException {
//		DataType dt = null;
//		String dtName = "";
//		dtString = DataTypeHelper.stripWhiteSpace(dtString);
//		DataTypeComponent element = getComponent(rowIndex);
//		if (element != null) {
//			dt = element.getDataType();
//			dtName = dt.getDisplayName();
//			if (dtString.equals(dtName)) {
//				return DataTypeInstance.getDataTypeInstance(element.getDataType(),
//					element.getLength(), usesAlignedLengthComponents());
//			}
//		}
//
//		int newLength = 0;
//		DataType newDt = DataTypeHelper.parseDataType(rowIndex, dtString, this, originalDTM,
//			provider.dtmService);
//		if (newDt == null) {
//			if (dt != null) {
//				throw new UsrException("No data type was specified.");
//			}
//			throw new AssertException("Can't set data type to null.");
//		}
//
//		checkIsAllowableDataType(newDt);
//
//		newLength = newDt.getLength();
//		if (newLength < 0) {
//			DataTypeInstance sizedDataType = DataTypeHelper.getSizedDataType(provider, newDt,
//				lastNumBytes, getMaxReplaceLength(rowIndex));
//			newLength = sizedDataType.getLength();
//		}
//
//		newDt = viewDTM.resolve(newDt, null);
//		int maxLength = getMaxReplaceLength(rowIndex);
//		if (newLength <= 0) {
//			throw new UsrException("Can't currently add this data type.");
//		}
//		if (maxLength > 0 && newLength > maxLength) {
//			throw new UsrException(newDt.getDisplayName() + " doesn't fit.");
//		}
//		return DataTypeInstance.getDataTypeInstance(newDt, newLength,
//			usesAlignedLengthComponents());
//	}

	@SuppressWarnings("unused") // the exception is thrown by subclasses
	protected void validateComponentName(int rowIndex, String name) throws UsrException {
		// If the name actually needs validating then override this method.
	}

	private void checkName(String name) throws DuplicateNameException {
		DataType dt = originalDTM.getDataType(getOriginalCategoryPath(), name);
		if (dt != null && originalDTM.getID(dt) != originalCompositeId) {
			throw new DuplicateNameException("Data type named " + name + " already exists");
		}
	}

	/**
	 * @return true if presence of bitfields is supported, else false
	 */
	protected boolean bitfieldsSupported() {
		return (viewComposite instanceof Structure) || (viewComposite instanceof Union);
	}

	/**
	 * Get the composite edtor's datatype manager
	 * @return composite edtor's datatype manager
	 */
	public CompositeViewerDataTypeManager<T> getViewDataTypeManager() {
		return viewDTM;
	}

}
