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

import ghidra.app.util.datatype.EmptyCompositeException;
import ghidra.program.model.data.*;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public interface EditorModel {

	/**
	 * Loads the specified composite into the model replacing
	 * whatever composite is there.
	 *
	 * @param dataType the new composite data type.
	 * @param offline false indicates don't try to keep the composite itself
	 * in the editor's data type manager.
	 */
	public void load(Composite dataType, boolean offline);

	/**
	 * Called when the model is no longer needed. 
	 * This is where all cleanup code for the model should be placed.
	 */
	public void dispose();

	/**
	 * Returns the docking windows component provider associated with this edit model.
	 * @return the component provider
	 */
	public CompositeEditorProvider getProvider();

	/**
	 * Adds a CompositeEditorModelListener to be notified when changes occur.
	 * @param listener the listener to add.
	 */
	public void addCompositeEditorModelListener(CompositeEditorModelListener listener);

	/**
	 * Removes a CompositeEditorModelListener that was being notified when changes occur.
	 * @param listener the listener to remove.
	 */
	public void removeCompositeEditorModelListener(CompositeEditorModelListener listener);

	/**
	 * Gets a data type within this editor that is equivalent to the indicated data type.
	 * @param dt the data type to resolve
	 * @return the equivalent data type within this editor.
	 */
	public DataType resolve(DataType dt);

	/**
	 * Returns whether or not addition of the specified component is allowed
	 * based on the current selection. the addition could be an insert or replace as
	 * determined by the state of the edit model.
	 *
	 * @param datatype the data type to be added.
	 */
	public boolean isAddAllowed(DataType datatype);

	/**
	 * Returns whether or not addition of the specified component is allowed
	 * at the specified index. the addition could be an insert or replace as
	 * determined by the state of the edit model.
	 *
	 * @param rowIndex row index of the component in the composite data type.
	 * @param datatype the data type to be inserted.
	 */
	public boolean isAddAllowed(int rowIndex, DataType datatype);

	/**
	 * Returns whether or not the selection is allowed to be changed into an array.
	 */
	public boolean isArrayAllowed();

	/**
	 * Returns whether or not a bitfield is allowed at the current location.
	 */
	public boolean isBitFieldAllowed();

	/**
	 * Returns whether or not clearing the selected components is allowed.
	 */
	public boolean isClearAllowed();

	/**
	 * Returns whether or not the current selection can be cycled using the
	 * indicated cycle group.
	 * @param cycleGroup the cycle group
	 * @return true, so that a message can be written to the user indicating
	 * the criteria for cycling.
	 */
	public boolean isCycleAllowed(CycleGroup cycleGroup);

	/**
	 * Returns whether or not the selected components can be deleted.
	 */
	public boolean isDeleteAllowed();

	/**
	 * Returns whether or not the component at the selected index
	 * is allowed to be duplicated.
	 */
	public boolean isDuplicateAllowed();

	/**
	 * Returns whether or not the base type of the component at the
	 * selected index is editable. If the base type is a composite
	 * then it is editable.
	 * Also, if there isn't a selection then it isn't allowed.
	 */
	public boolean isEditComponentAllowed();

	/**
	 * 
	 * @param rowIndex
	 * @param column
	 * @return
	 */
	public boolean isEditFieldAllowed(int rowIndex, int column);

//	/**
//	 * Returns whether or not insertion of the specified data type is allowed
//	 * at the specified index.
//	 *
//	 * @param index index of the component in the union.
//	 * @param datatype the data type to be inserted.
//	 */
//	public boolean isInsertAllowed(DataType datatype);

	/**
	 * Returns whether or not insertion of the specified data type is allowed
	 * at the specified index.
	 *
	 * @param rowIndex row index of the component in the composite data type.
	 * @param datatype the data type to be inserted.
	 */
	public boolean isInsertAllowed(int rowIndex, DataType datatype);

	/**
	 * Returns whether the selected component(s) can be moved down (to the next higher index).
	 */
	public boolean isMoveDownAllowed();

	/**
	 * Returns whether the selected component(s) can be moved up (to the next lower index).
	 */
	public boolean isMoveUpAllowed();

//	/**
//	 * 
//	 * @param dataType
//	 * @return
//	 */
//	public boolean isReplaceAllowed(DataType dataType);

	/**
	 * 
	 * @param rowIndex row index of the component in the composite data type.
	 * @param dataType
	 * @return
	 */
	public boolean isReplaceAllowed(int rowIndex, DataType dataType);

	/**
	 * Returns whether the selected component can be unpackaged.
	 */
	public boolean isUnpackageAllowed();

	/**
	 * Returns whether or not the editor has changes that haven't been applied.
	 * Changes can also mean a new data type that hasn't yet been saved.
	 */
	public boolean hasChanges();

	/**
	 *  Sets the name for the composite data type being edited.
	 *
	 * @param name the new name.
	 * 
	 * @throws DuplicateNameException if the name already exists.
	 */
	public void setName(String name) throws DuplicateNameException, InvalidNameException;

	/**
	 *  Sets the description for the composite data type being edited.
	 *
	 * @param desc the new description.
	 */
	public void setDescription(String desc);

	/**
	 * Sets the data type for the component at the indicated rowIndex.
	 * @param rowIndex the row index of the component 
	 * @param dataTypeObject a String or a DataType
	 */
	public void setComponentDataType(int rowIndex, Object dataTypeObject) throws UsrException;

	/**
	 * Sets the data type for the component at the indicated row index.
	 * @param rowIndex the row index of the component 
	 * @param dataTypeInstance
	 */
	public void setComponentDataTypeInstance(int rowIndex, DataTypeInstance dataTypeInstance)
			throws UsrException;

	/**
	 * Sets the data type for the component at the indicated index.
	 * @param rowIndex the row index of the component 
	 * @param name
	 */
	public void setComponentName(int rowIndex, String name)
			throws InvalidInputException, InvalidNameException, DuplicateNameException;

	/**
	 * Sets the data type for the component at the indicated index.
	 * @param rowIndex the row index of the component 
	 * @param comment
	 */
	public void setComponentComment(int rowIndex, String comment) throws InvalidInputException;

	/**
	 *  Returns whether or not the editor is showing undefined bytes.
	 *  @return true if the editor is showing undefined bytes.
	 */
	public boolean isShowingUndefinedBytes();

	/**
	 * Gets the column number of the first editable field found for the indicated row.
	 * 
	 * @param rowIndex the index number of the row
	 * @return the index number of the editable column or -1 if no fields are editable.
	 */
	public int getFirstEditableColumn(int rowIndex);

	/**
	 * 
	 * @param rowIndex
	 * @param column
	 * @return
	 */
	public boolean beginEditingField(int rowIndex, int column);

	/**
	 *  Change the edit state to indicate no longer editing a field.
	 */
	public boolean endEditingField();

	/**
	 *  Returns whether the user is currently editing a field's value.
	 */
	public boolean isEditingField();

	/**
	 * 
	 */
	public void endFieldEditing();

	/**
	 * 
	 * @param dataType
	 * @return
	 * @throws UsrException
	 */
	public DataTypeComponent add(DataType dataType) throws UsrException;

	/**
	 * 
	 * @param rowIndex
	 * @param dataType
	 * @return
	 * @throws UsrException
	 */
	public DataTypeComponent add(int rowIndex, DataType dataType) throws UsrException;

	/**
	 * 
	 * @param rowIndex
	 * @param dt
	 * @param dtLength
	 * @return
	 * @throws UsrException
	 */
	public DataTypeComponent add(int rowIndex, DataType dt, int dtLength) throws UsrException;

	/**
	 * Apply the changes for the current edited composite back to the
	 * original composite.
	 *
	 * @return true if apply succeeds
	 * @throws EmptyCompositeException if the structure doesn't have any components.
	 * @throws InvalidDataTypeException if this structure has a component that it is part of.
	 */
	public boolean apply() throws EmptyCompositeException, InvalidDataTypeException;

	public void clearComponent(int rowIndex);

	/**
	 * 
	 * @throws UsrException
	 */
	public void clearSelectedComponents() throws UsrException;

	/**
	 * @param cycleGroup
	 */
	public void cycleDataType(CycleGroup cycleGroup);

	/**
	 * Create array component
	 * @throws UsrException
	 */
	public void createArray() throws UsrException;

	/**
	 *  Delete the selected components.
	 *
	 * @throws UsrException if the data type isn't allowed to be deleted.
	 */
	public void deleteSelectedComponents() throws UsrException;

	/**
	 * Creates multiple duplicates of the indicated component.
	 * The duplicates will be created at the index immediately after the 
	 * indicated component.
	 * @param rowIndex the index of the row whose component is to be duplicated.
	 * @param multiple the number of duplicates to create.
	 * @param monitor the task monitor
	 * @throws UsrException if component can't be duplicated the indicated number of times.
	 */
	public void duplicateMultiple(int rowIndex, int multiple, TaskMonitor monitor)
			throws UsrException;

	/**
	 * 
	 * @param dataType
	 * @return
	 * @throws UsrException
	 */
	public DataTypeComponent insert(DataType dataType) throws UsrException;

	/**
	 * 
	 * @param rowIndex
	 * @param dataType
	 * @return
	 * @throws UsrException
	 */
	public DataTypeComponent insert(int rowIndex, DataType dataType) throws UsrException;

	/**
	 * 
	 * @param rowIndex
	 * @param dt
	 * @param dtLength
	 * @return
	 * @throws UsrException
	 */
	public DataTypeComponent insert(int rowIndex, DataType dt, int dtLength) throws UsrException;

	/**
	 * Moves a contiguous selection of components up by a single position. 
	 * The component that was immediately above 
	 * (at the index immediately preceeding the selection)
	 * the selection will be moved below the selection 
	 * (to what was the maximum selected component index).
	 * @return true if selected components were moved up.
	 * @throws UsrException if components can't be moved up.
	 */
	public boolean moveUp() throws UsrException;

	/**
	 * Moves a contiguous selection of components down by a single position. 
	 * The component that was immediately below 
	 * (at the index immediately following the selection)
	 * the selection will be moved above the selection 
	 * (to what was the minimum selected component index).
	 * @return true if selected components were moved down.
	 * @throws UsrException if components can't be moved down.
	 */
	public boolean moveDown() throws UsrException;

//	/**
//	 * 
//	 * @param dataType
//	 * @return
//	 * @throws UsrException
//	 */
//	public DataTypeComponent replace(DataType dataType) throws UsrException;
//
//	/**
//	 * 
//	 * @param rowIndex
//	 * @param dataType
//	 * @return
//	 * @throws UsrException
//	 */
//	public DataTypeComponent replace(int rowIndex, DataType dataType) throws UsrException;

	/**
	 * 
	 * @param rowIndex
	 * @param dt
	 * @param dtLength
	 * @return
	 * @throws UsrException
	 */
	public DataTypeComponent replace(int rowIndex, DataType dt, int dtLength) throws UsrException;

	/**
	 * Gets the maximum number of bytes available for a data type that is added at the indicated
	 * index. This can vary based on whether or not it is in a selection. 
	 *
	 * @param rowIndex index of the row in the editor's composite data type.
	 */
	public int getMaxAddLength(int rowIndex);

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
	public int getMaxDuplicates(int rowIndex);

	/**
	 * Determine the maximum number of array elements that can be created for 
	 * the current selection. The array data type is assumed to become the
	 * data type of the first component in the selection. The current selection
	 * must be contiguous or 0 is returned.
	 *
	 * @return the number of array elements that fit in the current selection.
	 */
	public int getMaxElements();

	/**
	 * Gets the maximum number of bytes available for a new data type that 
	 * will replace the current data type at the indicated component index.
	 * If there isn't a component with the indicated index, the max length 
	 * will be determined by the lock mode.
	 *
	 * @param rowIndex index of the row for the component to replace.
	 * @return the maximum number of bytes that can be replaced.
	 */
	public int getMaxReplaceLength(int rowIndex);

	/**
	 * Return the last number of bytes the user entered when prompted for 
	 * a data type size.
	 * @return the number of bytes
	 */
	public int getLastNumBytes();

	/**
	 * Return the last number of duplicates the user entered when prompted for 
	 * creating duplicates of a component.
	 * @return the number of duplicates
	 */
	public int getLastNumDuplicates();

	/**
	 * Return the last number of elements the user entered when prompted for 
	 * creating an array.
	 * @return the number of elements
	 */
	public int getLastNumElements();

}
