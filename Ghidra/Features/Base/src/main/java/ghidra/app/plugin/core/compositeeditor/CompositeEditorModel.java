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

import java.util.ArrayList;

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
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.util.*;
import ghidra.util.exception.*;

/**
 * Model for editing a composite data type. Specific composite data type editors
 * should extend this class.
 */
public abstract class CompositeEditorModel extends CompositeViewerModel implements EditorModel {

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

	private boolean offline = true;
	protected boolean hadChanges = false;
	protected boolean originalIsChanging = false;

	protected ArrayList<CompositeEditorModelListener> listeners = new ArrayList<>(1);

	public CompositeEditorModel(CompositeEditorProvider provider) {
		super(provider);
	}

	@Override
	public void load(Composite dataType, boolean useOffLineCategory) {
		this.offline = useOffLineCategory;
		if (dataType == null) {
			return;
//			throw new NullPointerException();
		}
		DataTypeManager dataTypeManager = dataType.getDataTypeManager();
		if (dataTypeManager == null) {
			throw new IllegalArgumentException(
				"Datatype " + dataType.getName() + " doesn't have a data type manager specified.");
		}
		CategoryPath categoryPath = dataType.getCategoryPath();
		Category cat = dataTypeManager.getCategory(categoryPath);
		if (cat == null && !useOffLineCategory) {
			throw new IllegalArgumentException(
				"Datatype " + dataType.getName() + " category not found: " +
					categoryPath.getPath());
		}
		if (isEditingField()) {
			endFieldEditing();
		}
		DataTypeManager originalDTM = getOriginalDataTypeManager();
		if (isLoaded()) {
			// No longer want to listen for changes to previous category.
			if (originalDTM != null) {
				originalDTM.removeDataTypeManagerListener(this);
			}
			unload();
		}

		// DataType should be a Composite.
		originalComposite = dataType;
		originalDataTypePath = originalComposite.getDataTypePath();
		currentName = dataType.getName();
		originalDTM = dataTypeManager;
		if (useOffLineCategory) {
			viewDTM = new CompositeViewerDataTypeManager(originalDTM.getName(), dataType);
			viewComposite = (Composite) viewDTM.resolve(dataType, null);
		}
		else {
			viewDTM = originalDTM;
			viewComposite = (Composite) dataType.clone(viewDTM);
		}
		// Listen so we can update editor if name changes for this structure.
		if (originalDTM.contains(dataType)) {
			compositeID = originalDTM.getID(dataType); // Get the id if editing an existing data type.
		}
		originalDTM.addDataTypeManagerListener(this);

		hadChanges = false;
		setSelection(new FieldSelection());
		clearStatus();
		originalNameChanged();
		originalCategoryChanged();
		compositeInfoChanged();
		fireTableDataChanged();
		componentDataChanged();

		editorStateChanged(CompositeEditorModelListener.COMPOSITE_LOADED);
	}

	@Override
	public void dispose() {
		super.dispose();
	}

	@Override
	public CompositeEditorProvider getProvider() {
		return provider;
	}

	@Override
	public void addCompositeEditorModelListener(CompositeEditorModelListener listener) {
		listeners.add(listener);
		super.addCompositeViewerModelListener(listener);
	}

	@Override
	public void removeCompositeEditorModelListener(CompositeEditorModelListener listener) {
		listeners.remove(listener);
		super.removeCompositeViewerModelListener(listener);
	}

	@Override
	public DataType resolve(DataType dt) {
		return viewDTM.resolve(dt, null);
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

		return DataTypeInstance.getDataTypeInstance(resultDt, resultLen);
	}

	/**
	 * Notification that a field edit has ended.
	 */
	@Override
	public void endFieldEditing() {
		if (!isEditingField()) {
			return;
		}
		for (CompositeEditorModelListener listener : listeners) {
			listener.endFieldEditing();
		}
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
				setComponentDataType(rowIndex, value);
			}
			else if (columnIndex == getNameColumn()) {
				setComponentName(rowIndex, ((String) value).trim());
			}
			else if (columnIndex == getCommentColumn()) {
				setComponentComment(rowIndex, (String) value);
			}
			else {
				return false;
			}
			return true;
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
	 *  Sets the name for the structure being edited.
	 *
	 * @param name the new name.
	 * 
	 * @throws DuplicateNameException if the name already exists.
	 */
	@Override
	public void setName(String name) throws DuplicateNameException, InvalidNameException {
		if (name.equals(currentName)) {
			return;
		}
		currentName = name;
		boolean nameModified = !currentName.equals(getOriginalDataTypeName());
		updateAndCheckChangeState();
		// Notify any listeners that the name modification state has changed.
		int type = (nameModified) ? CompositeEditorModelListener.COMPOSITE_MODIFIED
				: CompositeEditorModelListener.COMPOSITE_UNMODIFIED;
		editorStateChanged(type);
		if (viewComposite != null) {
			validName = false;
			viewComposite.setName(name);
			checkName(name);
			validName = true;
		}
	}

	/**
	 *  Return the currently specified data type name of the composite being viewed.
	 */
	@Override
	public String getCompositeName() {
		return currentName;
	}

	/**
	 *  Sets the description for the composite being edited.
	 *
	 * @param desc the new description.
	 */
	@Override
	public void setDescription(String desc) {
		Composite original = this.getOriginalComposite();
		boolean descriptionModified = (original != null) && !desc.equals(original.getDescription());
		if (viewComposite != null) {
			if (!desc.equals(viewComposite.getDescription())) {
				viewComposite.setDescription(desc);
			}
		}
		updateAndCheckChangeState();
		// Notify any listeners that the name modification state has changed.
		int type = (descriptionModified) ? CompositeEditorModelListener.COMPOSITE_MODIFIED
				: CompositeEditorModelListener.COMPOSITE_UNMODIFIED;
		editorStateChanged(type);
	}

	@Override
	public void setComponentDataType(int rowIndex, Object dataTypeObject) throws UsrException {
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
		int newLength = -1;
		if (dataTypeObject instanceof DataTypeInstance) {
			DataTypeInstance dti = (DataTypeInstance) dataTypeObject;
			newDt = dti.getDataType();
			newLength = dti.getLength();
		}
		else if (dataTypeObject instanceof DataType) {
			newDt = (DataType) dataTypeObject;
			newLength = newDt.getLength();
		}
		else if (dataTypeObject instanceof String) {
			String dtString = (String) dataTypeObject;
			if (dtString.equals(dtName)) {
				return;
			}
			DataTypeManager originalDTM = getOriginalDataTypeManager();
			newDt = DataTypeHelper.parseDataType(rowIndex, dtString, this, originalDTM,
				provider.dtmService);
			newLength = newDt.getLength();
		}
		if (newDt == null) {
			return; // Was nothing and is nothing.
		}
		
		if (DataTypeComponent.usesZeroLengthComponent(newDt)) {
			newLength = 0;
		}

		checkIsAllowableDataType(newDt);

		newDt = resolveDataType(newDt, viewDTM, DataTypeConflictHandler.DEFAULT_HANDLER);
		
		if (newLength < 0) {
			// prefer previous size first
			int suggestedLength = (previousLength <= 0) ? lastNumBytes : previousLength;
			DataTypeInstance sizedDataType = DataTypeHelper.getSizedDataType(provider, newDt,
				suggestedLength, getMaxReplaceLength(rowIndex));
			if (sizedDataType == null) {
				return;
			}
			newDt = resolveDataType(sizedDataType.getDataType(),  viewDTM, DataTypeConflictHandler.DEFAULT_HANDLER);
			newLength = sizedDataType.getLength();
			if (newLength <= 0) {
				throw new UsrException("Can't currently add this data type.");
			}
		}
		if ((previousDt != null) && newDt.isEquivalent(previousDt) && newLength == previousLength) {
			return;
		}

		int maxLength = getMaxReplaceLength(rowIndex);
		if (maxLength > 0 && newLength > maxLength) {
			throw new UsrException(newDt.getDisplayName() + " doesn't fit within " + maxLength +
				" bytes, need " + newLength + " bytes");
		}
		setComponentDataTypeInstance(rowIndex, newDt, newLength);
		notifyCompositeChanged();
	}

	/**
	 * Resolves the data type against the indicated data type manager using the specified conflictHandler.
	 * Transactions should have already been initiated prior to calling this method. 
	 * If not then override this method to perform the transaction code around the resolve.
	 * 
	 * @param dt the data type to be resolved
	 * @param resolveDtm the data type manager to resolve the data type against
	 * @param conflictHandler the handler to be used for any conflicts encountered while resolving
	 * @return the resolved data type
	 */
	public DataType resolveDataType(DataType dt, DataTypeManager resolveDtm,
			DataTypeConflictHandler conflictHandler) {
		return resolveDtm.resolve(dt, conflictHandler);
	}

	@SuppressWarnings("unused") // the exception is thrown by subclasses1d
	protected void clearComponents(int[] rows) throws UsrException {
		for (int i = rows.length - 1; i >= 0; i--) {
			clearComponent(rows[i]);
		}
		notifyCompositeChanged();
	}

	protected void deleteComponents(int[] rows) {
		for (int i = rows.length - 1; i >= 0; i--) {
			deleteComponent(rows[i]);
		}
		notifyCompositeChanged();
	}

	protected abstract void deleteComponent(int rowIndex);

	/**
	 *  Clear the selected components.
	 *
	 * @throws UsrException if the data type isn't allowed to be cleared.
	 */
	@Override
	public void createArray() throws UsrException {
		if (!isArrayAllowed()) {
			throw new UsrException("Array not permitted in current context");
		}
		int min = 1;
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

	protected void createArray(int numElements)
			throws InvalidDataTypeException, DataTypeConflictException, UsrException {
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
	@Override
	public void clearSelectedComponents() throws UsrException {
		if (!isClearAllowed()) {
			throw new UsrException("Clearing is not allowed.");
		}
		if (isEditingField()) {
			endFieldEditing();
		}
		clearComponents(getSelectedComponentRows());
	}

	@Override
	public void deleteSelectedComponents() throws UsrException {
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
	 * Returns true if this composite editor model is editing the composite in
	 * an offline data type manager instance. In other words, changes to the data type
	 * being edited don't directly affect the original data type manager is unaffected
	 * until editor changes are applied.
	 * 
	 * <p>If this returns false, then the editor directly affects the original
	 * data type manager. For example, as data types are added to the composite data type,
	 * they are also added to the original data type manager if not already there.
	 * 
	 * @return true if editing offline
	 */
	public boolean isOffline() {
		return offline;
	}

	@Override
	public boolean hasChanges() {
		return hadChanges;
	}

	public boolean updateAndCheckChangeState() {
		if (originalIsChanging) {
			return false;
		}
		Composite oldComposite = getOriginalComposite();
		String oldName = getOriginalDataTypeName();
		String newDesc = viewComposite.getDescription();
		if (newDesc == null) {
			newDesc = "";
		}
		String oldDesc = oldComposite != null ? oldComposite.getDescription() : "";
		if (oldDesc == null) {
			oldDesc = "";
		}
		boolean noCompChanges = false;
		if (oldComposite != null) {
			noCompChanges = (viewComposite.isEquivalent(oldComposite) &&
				!hasCompPathNameChanges(viewComposite, oldComposite));
		}
		else {
			noCompChanges = getNumComponents() == 0;
		}
		hadChanges = !(currentName.equals(oldName) && newDesc.equals(oldDesc) && noCompChanges);
		return hadChanges;
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

	@Override
	public boolean beginEditingField(int rowIndex, int columnIndex) {
		if (isEditingField()) {
			return false;
		}
		try {
			stillBeginningEdit = true; // We want to know we are still beginning an edit when we fix the selection.
			editingField = true;
			setLocation(rowIndex, columnIndex);
			setSelection(new int[] { rowIndex });
			notifyEditingChanged();
		}
		finally {
			stillBeginningEdit = false;
		}
		return true;
	}

	@Override
	public boolean endEditingField() {
		if (!isEditingField()) {
			return false;
		}
		editingField = false;
		notifyEditingChanged();
		return true;
	}

	@Override
	public boolean isEditingField() {
		return !settingValueAt && editingField;
	}

	@Override
	public int getFirstEditableColumn(int rowIndex) {
		int numFields = this.getColumnCount();
		for (int i = 0; i < numFields; i++) {
			if (this.isCellEditable(rowIndex, i)) {
				return i;
			}
		}
		return -1;
	}

	private void notifyEditingChanged() {
		for (CompositeEditorModelListener listener : listeners) {
			listener.compositeEditStateChanged(
				isEditingField() ? CompositeEditorModelListener.EDIT_STARTED
						: CompositeEditorModelListener.EDIT_ENDED);
		}
	}

	@Override
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
				DataTypeInstance dti = DataTypeHelper.getFixedLength(this, currentIndex, dt);
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
	protected void checkIsAllowableDataType(DataType datatype)
			throws InvalidDataTypeException {
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

	@Override
	public boolean isAddAllowed(int currentIndex, DataType datatype) {
		return false;
	}

	@Override
	public boolean isArrayAllowed() {
		return false;
	}

	@Override
	public boolean isClearAllowed() {
		return false;
	}

	@Override
	public boolean isCycleAllowed(CycleGroup cycleGroup) {
		return false;
	}

	@Override
	public boolean isDeleteAllowed() {
		return false;
	}

	@Override
	public boolean isDuplicateAllowed() {
		return false;
	}

	@Override
	public boolean isEditComponentAllowed() {
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
			((baseDt instanceof Structure) || baseDt instanceof Union || baseDt instanceof Enum));
	}

	@Override
	public boolean isEditFieldAllowed(int rowIndex, int columnIndex) {
		return !isEditingField();
	}

	@Override
	public boolean isInsertAllowed(int rowIndex, DataType datatype) {
		return false;
	}

	@Override
	public boolean isMoveDownAllowed() {
		return false;
	}

	@Override
	public boolean isMoveUpAllowed() {
		return false;
	}

	@Override
	public boolean isReplaceAllowed(int rowIndex, DataType dataType) {
		return false;
	}

	@Override
	public boolean isUnpackageAllowed() {
		return false;
	}

	@Override
	public void dataTypeRenamed(DataTypeManager dtm, DataTypePath oldPath, DataTypePath newPath) {
		if (!isLoaded()) {
			return;
		}
		if (oldPath.getDataTypeName().equals(newPath.getDataTypeName())) {
			return;
		}
		if (originalDataTypePath == null) {
			return;
		}
		String newName = newPath.getDataTypeName();
		String oldName = oldPath.getDataTypeName();

		// Does the old name match our original name.
		if (originalDataTypePath.equals(oldPath)) {
			originalDataTypePath = newPath;
			try {
				if (viewComposite.getName().equals(oldName)) {
					setName(newName);
					compositeInfoChanged();
				}
			}
			catch (DuplicateNameException e) {
				Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			}
			catch (InvalidNameException e) {
				Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			}
			originalNameChanged();
		}
		else {
			DataType dt = viewDTM.getDataType(oldPath);
			if (dt != null) {
				try {
					dt.setName(newName);
					fireTableDataChanged();
					componentDataChanged();
				}
				catch (InvalidNameException e) {
					Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
				}
				catch (DuplicateNameException e) {
					Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
				}
			}
		}
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

	@Override
	public int getLastNumBytes() {
		return lastNumBytes;
	}

	@Override
	public int getLastNumDuplicates() {
		return lastNumDuplicates;
	}

	@Override
	public int getLastNumElements() {
		return lastNumElements;
	}

	/**
	 * Sets the last number of bytes the user entered for a data type
	 * @param numBytes the last number of bytes entered
	 */
	public void setLastNumBytes(int numBytes) {
		lastNumBytes = numBytes;
	}

	/**
	 * Sets the last number of bytes the user entered for a data type
	 * @param numDuplicates the last number of bytes entered
	 */
	public void setLastNumDuplicates(int numDuplicates) {
		lastNumDuplicates = numDuplicates;
	}

	/**
	 * Sets the last number of bytes the user entered for a data type
	 * @param numElements the last number of bytes entered
	 */
	public void setLastNumElements(int numElements) {
		lastNumElements = numElements;
	}

//==================================================================================================
// End of methods for determining if a type of edit action is allowed
//==================================================================================================	

	@Override
	protected Composite getOriginalComposite() {
		if (!offline) {
			return originalComposite;
		}
		return super.getOriginalComposite();
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
		adjustCurrentRow();
		selectionChanged();
	}

	@SuppressWarnings("unused") // the exception is thrown by subclasses1
	public void validateComponentOffset(int rowIndex, String offset) throws UsrException {
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
	public DataTypeInstance validateComponentDataType(int rowIndex, String dtString)
			throws UsrException {
		DataType dt = null;
		String dtName = "";
		dtString = DataTypeHelper.stripWhiteSpace(dtString);
		DataTypeComponent element = getComponent(rowIndex);
		if (element != null) {
			dt = element.getDataType();
			dtName = dt.getDisplayName();
			if (dtString.equals(dtName)) {
				return DataTypeInstance.getDataTypeInstance(element.getDataType(),
					element.getLength());
			}
		}

		int newLength = 0;
		DataTypeManager originalDTM = getOriginalDataTypeManager();
		DataType newDt = DataTypeHelper.parseDataType(rowIndex, dtString, this, originalDTM,
			provider.dtmService);
		if (newDt == null) {
			if (dt != null) {
				throw new UsrException("No data type was specified.");
			}
			throw new AssertException("Can't set data type to null.");
		}

		checkIsAllowableDataType(newDt);

		newLength = newDt.getLength();
		if (newLength < 0) {
			DataTypeInstance sizedDataType = DataTypeHelper.getSizedDataType(provider, newDt,
				lastNumBytes, getMaxReplaceLength(rowIndex));
			newLength = sizedDataType.getLength();
		}

		newDt = viewDTM.resolve(newDt, null);
		int maxLength = getMaxReplaceLength(rowIndex);
		if (newLength <= 0) {
			throw new UsrException("Can't currently add this data type.");
		}
		if (maxLength > 0 && newLength > maxLength) {
			throw new UsrException(newDt.getDisplayName() + " doesn't fit.");
		}
		return DataTypeInstance.getDataTypeInstance(newDt, newLength);
	}

	@SuppressWarnings("unused") // the exception is thrown by subclasses
	public void validateComponentName(int rowIndex, String name) throws UsrException {
		// If the name actually needs validating then override this method.
	}

	private void checkName(String name) throws DuplicateNameException {
		DataTypeManager originalDTM = getOriginalDataTypeManager();
		DataType dt = originalDTM.getDataType(getOriginalCategoryPath(), name);
		if (dt != null && dt != originalComposite) {
			throw new DuplicateNameException("Data type named " + name + " already exists");
		}
	}

	/**
	 * @return true if presence of bitfields is supported, else false
	 */
	protected boolean bitfieldsSupported() {
		return (viewComposite instanceof Structure) || (viewComposite instanceof Union);
	}

}
