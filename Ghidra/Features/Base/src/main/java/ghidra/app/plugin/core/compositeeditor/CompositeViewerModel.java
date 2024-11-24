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
import java.util.function.Consumer;

import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumn;

import docking.widgets.fieldpanel.support.FieldRange;
import docking.widgets.fieldpanel.support.FieldSelection;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.data.*;
import ghidra.util.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import utility.function.Callback;

abstract class CompositeViewerModel extends AbstractTableModel
		implements DataTypeManagerChangeListener {

	/**
	 * Flag indicating that the model is updating the selection and should ignore any attempts to
	 * set the selection until it is no longer updating.
	 */
	protected boolean updatingSelection = false;

	protected Composite originalComposite;
	protected DataTypePath originalDataTypePath;
	protected long originalCompositeId;
	protected DataTypeManager originalDTM;

	protected Composite viewComposite;
	protected CompositeViewerDataTypeManager viewDTM;

	private List<CompositeViewerModelListener> modelListeners = new ArrayList<>();

	/** the current status */
	private String status = "";

	/** The selection associated with the components. */
	protected FieldSelection selection;

	// The fields for each component.
	/** The column headers for the component edit area. */
	protected String headers[] =
		{ "Offset", "Length", "Mnemonic", "DataType", "FieldName", "Comment" };
	private static final int OFFSET = 0;
	private static final int LENGTH = 1;
	private static final int MNEMONIC = 2;
	private static final int DATATYPE = 3;
	private static final int NAME = 4;
	private static final int COMMENT = 5;

	/** Offset of each component field. */
	protected int[] columnOffsets = new int[headers.length];
	/** Width of each component field. */
	protected int[] columnWidths = { 75, 75, 100, 100, 100, 150 }; // Initial default column widths
	/** Total component area width. */
	protected int width = 0;
	/** Width of left margin in pixels for the component area. */
	protected int leftMargin = 10;
	/** the current row for a field edit */
	protected int currentEditRow = -1;
	/** the current column for a field edit */
	protected int currentEditColumn = -1;
	protected CompositeEditorProvider provider;
	protected boolean showHexNumbers = false;

	CompositeViewerModel(CompositeEditorProvider provider) {
		this.provider = provider;
		selection = new FieldSelection();
		adjustWidth();
		adjustOffsets();
	}

	/**
	 * Returns <code>String.class</code> regardless of <code>columnIndex</code>.
	 *
	 * @param columnIndex  the column being queried
	 * @return the String.class
	 */
	@Override
	public Class<?> getColumnClass(int columnIndex) {
		if (columnIndex == getDataTypeColumn()) {
			return DataTypeInstance.class;
		}
		return String.class;
	}

	public int getOffsetColumn() {
		return OFFSET;
	}

	public int getLengthColumn() {
		return LENGTH;
	}

	public int getMnemonicColumn() {
		return MNEMONIC;
	}

	public int getDataTypeColumn() {
		return DATATYPE;
	}

	public int getNameColumn() {
		return NAME;
	}

	public int getCommentColumn() {
		return COMMENT;
	}

	// subclasses may supply columns
	protected List<TableColumn> getHiddenColumns() {
		return Collections.emptyList();
	}

	/**
	 * Terminates listening for category change events within the model.
	 */
	protected void dispose() {
		// Unregister the listeners.
		// No longer want to listen for changes to previous category.
		unload();
	}

	/**
	 * Returns whether or not the editor has a structure loaded.  If no structure is loaded then
	 * only unload() or dispose() methods should be called.
	 * 
	 * @return true if an editable structure is currently loaded in the model.
	 */
	public boolean isLoaded() {
		return (viewComposite != null);
	}

	/**
	 * Updates the model to now view the indicated data structure.  This method should cleanup from
	 * a previous load if necessary and must initialize the following model state:
	 * <ul>
	 * <li>originalComposite</li>
	 * <li>originalDataTypePath</li>
	 * <li>originalCompositeId</li>
	 * <li>originalDataTypePath</li>
	 * <li>viewComposite</li>
	 * <li>viewDTM</li>
	 * </ul>
	 *
	 * @param dataType the composite date type to be viewed.
	 */
	protected abstract void load(Composite dataType);

	/**
	 * Unloads the currently loaded composite data type.
	 * This should be called when the viewer is removed from view and
	 * and category/dataType changes no longer need to be listened for.
	 * It can also be called to unload the current composite before loading
	 * a new composite data type.
	 */
	void unload() {
		// Unregister the listeners.
		// No longer want to listen for changes to previous category.
		if (originalDTM != null) {
			originalDTM.removeDataTypeManagerListener(this);
			originalDTM = null;
		}
		originalDTM = null;
		originalComposite = null;
		originalCompositeId = DataTypeManager.NULL_DATATYPE_ID;
		viewComposite = null;
		originalDataTypePath = null;
		if (viewDTM != null) {
			viewDTM.close();
			viewDTM = null;
		}
	}

	/**
	 * Resolves the data type against the indicated data type manager using the specified
	 * conflictHandler.  In general, a transaction should have already been initiated prior to 
	 * calling this method so that the true nature of the transaction may be established for
	 * use with undo/redo (e.g., Set Datatype).
	 *
	 * @param dataType the data type to be resolved
	 * @param resolveDtm the data type manager to resolve the data type against
	 * @param conflictHandler the handler to be used for any conflicts encountered while resolving
	 * @return the resolved data type
	 */
	protected final DataType resolveDataType(DataType dataType, DataTypeManager resolveDtm,
			DataTypeConflictHandler conflictHandler) {
		if (resolveDtm == null || dataType == DataType.DEFAULT) {
			return DataType.DEFAULT;
		}
		return resolveDtm.withTransaction("Resolve " + dataType.getPathName(), () -> {
			return resolveDtm.resolve(dataType, conflictHandler);
		});
	}

	/**
	 * Resolves the indicated data type against the working copy in the viewer's data type manager.
	 * @param dataType the data type
	 * @return the working copy of the data type.
	 */
	public DataType resolve(DataType dataType) {
		return resolveDataType(dataType, viewDTM, null);
	}

	/**
	 * Gets the current row
	 * @return the current row
	 */
	public int getRow() {
		return currentEditRow;
	}

	/**
	 * Sets the current row to the indicated row
	 * @param row the new row
	 */
	public void setRow(int row) {
		this.currentEditRow = row;
	}

	/**
	 * Gets the current column
	 * @return the current column
	 */
	public int getColumn() {
		return currentEditColumn;
	}

	/**
	 * Sets the current column to the indicated column
	 * @param column the new column
	 */
	public void setColumn(int column) {
		if (updatingSelection) {
			// ignore transient events that happen while the table is being rebuilt, as these will
			// clear our notion of the last selected column
			return;
		}

		this.currentEditColumn = column;
	}

	/**
	 * Sets the current row and column to those indicated.
	 * @param row the new row
	 * @param column the new column
	 */
	protected void setLocation(int row, int column) {
		this.currentEditRow = row;
		this.currentEditColumn = column;
	}

	/**
	 * Returns the original Composite DataType that currently exists within the original 
	 * DataTypeManager, or if not found the instance originally loaded.
	 * @return the original composite being viewed or null if nothing is currently loaded in
	 * the model.
	 */
	protected Composite getOriginalComposite() {
		Composite existingOriginal = getExistingOriginalComposite();
		return existingOriginal != null ? existingOriginal : originalComposite;
	}

	/**
	 * Determine if the original composite exists within the original datatype manager.
	 * NOTE: If this method returns true, the current datatype which exists within the original
	 * datatype manager will be returned by {@link #getOriginalComposite()}, although its name
	 * may differ.
	 * @return true if datatype found else false
	 */
	protected boolean originalCompositeExists() {
		return getExistingOriginalComposite() != null;
	}

	private Composite getExistingOriginalComposite() {
		long originalId = getCompositeID();
		if (originalId != DataTypeManager.NULL_DATATYPE_ID && originalDataTypePath != null &&
			originalDTM != null) {
			DataType dt = originalDTM.getDataType(originalId);
			if (dt instanceof Composite &&
				DataTypeUtilities.isSameKindDataType(originalComposite, dt)) {
				return (Composite) dt;
			}
		}
		return null;
	}

	/**
	 * Returns the original name of the CompositeDataType being viewed
	 * @return the name
	 */
	public final String getOriginalDataTypeName() {
		return originalDataTypePath != null ? originalDataTypePath.getDataTypeName() : "";
	}

	/**
	 * Return the data type manager for the composite data type being viewed
	 * @return the manager
	 */
	protected DataTypeManager getOriginalDataTypeManager() {
		return originalDTM;
	}

	/**
	 * Return the original category for the composite data type being viewed
	 * @return the category
	 */
	public final Category getOriginalCategory() {
		if (originalDataTypePath != null && originalDTM != null) {
			CategoryPath originalCategoryPath = originalDataTypePath.getCategoryPath();
			if (originalDTM.containsCategory(originalCategoryPath)) {
				return originalDTM.getCategory(originalCategoryPath);
			}
		}
		return null;
	}

	/**
	 * Return the path of the data category for the structure being viewed
	 * @return the path
	 */
	public final CategoryPath getOriginalCategoryPath() {
		if (originalDataTypePath != null) {
			return originalDataTypePath.getCategoryPath();
		}
		return null;
	}

	/**
	 * Return the description for the structure being viewed
	 * @return the description
	 */
	public String getDescription() {
		String desc = null;
		if (viewComposite != null) {
			desc = viewComposite.getDescription();
		}
		return (desc != null) ? desc : "";
	}

	/**
	 * Return the size of the structure being viewed in bytes
	 * @return this size
	 */
	public int getLength() {
		if (viewComposite != null && !viewComposite.isZeroLength()) {
			return viewComposite.getLength();
		}
		return 0;
	}

	/**
	 * Return the size of the structure being viewed in bytes as a hex or decimal string depending
	 * on the model's current display setting for numbers
	 * @return the length
	 */
	public String getLengthAsString() {
		int length = getLength();
		return showHexNumbers ? getHexString(length, true) : Integer.toString(length);
	}

	/**
	 * Return the data type name of the structure being viewed
	 * @return the name
	 */
	protected String getCompositeName() {
		return (viewComposite != null) ? viewComposite.getDisplayName() : "";
	}

	/**
	 * Return the size of the left margin for the component viewing area
	 * @return the margin
	 */
	public int getLeftMargin() {
		return leftMargin;
	}

	/**
	 * Return a header name for the indicated column.
	 *
	 * @param columnIndex the index number indicating the component field (column) to get the
	 * header for.
	 */
	@Override
	public String getColumnName(int columnIndex) {
		return getFieldName(columnIndex);
	}

	/**
	 * Return a header name for the indicated field (column)
	 *
	 * @param columnIndex the index number indicating the component field (column) to get the
	 * header for
	 * @return the name
	 */
	public String getFieldName(int columnIndex) {
		if (columnIndex < 0) {
			return "UNKNOWN";
		}

		if (columnIndex < headers.length) {
			return headers[columnIndex];
		}

		List<TableColumn> hiddenColumns = getHiddenColumns();
		for (TableColumn c : hiddenColumns) {
			int modelIndex = c.getModelIndex();
			if (modelIndex == columnIndex) {
				return Objects.toString(c.getHeaderValue());
			}
		}

		return "UNKNOWN";
	}

	/**
	 * Returns whether or not a particular component row and field in this structure is an editable
	 * type of cell. However the cell still may not be editable currently. To check if the cell can
	 * actually be edited call isCellEditable().
	 *
	 * @param rowIndex the row index of the component
	 * @param columnIndex the index for the field of the component
	 * @return true if editable
	 */
	boolean isEditTypeOfCell(int rowIndex, int columnIndex) {
		return false; // User can't edit the cell.
	}

	/**
	 * Returns whether or not a particular component row and field in this structure is editable
	 *
	 * @param rowIndex index for the row (component within this structure).
	 * @param columnIndex index for the column (field of the component within this structure).
	 */
	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		return false;
	}

	/**
	 * Gets the display offset of the component field at the specified column index.
	 *
	 * @param columnIndex the field index within the component.
	 * @return the offset in pixels of the component field.
	 */
	int getFieldOffset(int columnIndex) {
		return ((columnIndex < 0 || columnIndex >= getColumnCount()) ? 0
				: columnOffsets[columnIndex]);
	}

	/**
	 * Gets the component display field offsets
	 * @return the offsets
	 */
	int[] getFieldOffsets() {
		return columnOffsets;
	}

	/**
	 * Adjusts the offsets of all component fields
	 */
	protected void adjustOffsets() {
		int offset = leftMargin;
		int numCols = getColumnCount();
		for (int i = 0; i < numCols; i++) {
			columnOffsets[i] = offset;
			offset += columnWidths[i];
		}
		this.width = offset;
	}

	/**
	 * Adjusts the total width of the component field area
	 */
	private void adjustWidth() {
		int newWidth = leftMargin;
		int numCols = getColumnCount();
		for (int i = 0; i < numCols; i++) {
			newWidth += columnWidths[i];
		}
		this.width = newWidth;
	}

	/**
	 * Gets the component display field area's total width
	 *
	 * @return the total width of the component field area
	 */
	public int getWidth() {
		return width;
	}

	/**
	 * Gets the display width of the component field at the specified column index.
	 *
	 * @param columnIndex the field index within the component
	 * @return the width of the component field
	 */
	public int getFieldWidth(int columnIndex) {
		return ((columnIndex < 0 || columnIndex >= getColumnCount()) ? 0
				: columnWidths[columnIndex]);
	}

	/**
	 * Returns the number of component rows in the viewer. There may be a blank row at the end for
	 * selecting. Therefore this number can be different than the actual number of components
	 * currently in the structure being viewed.
	 *
	 * @return the number of rows in the model
	 */
	@Override
	public int getRowCount() {
		return (viewComposite != null) ? viewComposite.getNumComponents() : 0;
	}

	/**
	 * Returns the number of components in this structure or union.
	 * @return the number of components in the model
	 */
	public int getNumComponents() {
		return (viewComposite != null) ? viewComposite.getNumComponents() : 0;
	}

	/**
	 * Return the nth component for the structure being viewed. Since the number of rows can exceed
	 * the number of components defined within the composite ({@link Composite#getNumComponents()})
	 * this method will return null for a blank row.
	 * 
	 * @param rowIndex the index of the component to return. First component is index of 0
	 * @return the component
	 */
	public DataTypeComponent getComponent(int rowIndex) {
		if (rowIndex >= 0 && rowIndex < getNumComponents()) {
			return viewComposite.getComponent(rowIndex);
		}
		return null;
	}

	/**
	 * Returns the number of columns (display fields) for each component in this structure or
	 * union.
	 *
	 * @return the number of display fields for each component
	 */
	@Override
	public int getColumnCount() {
		return headers.length;
	}

	/**
	 * Returns the number of display fields for this structure or union.
	 *
	 * @return the number of display fields for each component
	 */
	public int getNumFields() {
		return getColumnCount();
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {

		if ((viewComposite == null) || (rowIndex >= viewComposite.getNumComponents()) ||
			(rowIndex < 0) || (columnIndex < 0) || (columnIndex >= getColumnCount())) {
			if (columnIndex == getDataTypeColumn()) {
				return null;
			}
			return "";
		}
		String value;
		DataTypeComponent dtc = viewComposite.getComponent(rowIndex);
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
		else {
			value = "UNKNOWN";
		}
		return (value == null) ? "" : value;
	}

	/**
	 * Returns the current dataType name (Structure, Union, etc.) as a string.
	 * @return the type of composite being edited
	 */
	public abstract String getTypeName();

	/**
	 * Returns the current status string.
	 * @return the status
	 */
	public String getStatus() {
		return status;
	}

	/**
	 * Sets the current status string.
	 * @param status the status message
	 */
	public void setStatus(String status) {
		setStatus(status, false);
	}

	/**
	 * Sets the current status string and performs notification to all listeners.
	 * @param status the status message
	 * @param beep true indicates an audible beep should sound when the message is displayed
	 */
	public void setStatus(String status, boolean beep) {
		if (status == null) {
			status = "";
		}

		this.status = status;
		notify(modelListeners, listener -> listener.statusChanged(this.status, beep));
	}

	/**
	 *  Clears the current status string.
	 */
	public void clearStatus() {
		if (status.length() == 0) {
			return;
		}
		status = "";
		setStatus(status, false);
	}

	/**
	 * Adds a CompositeViewerModelListener to be notified when model changes occur
	 * @param listener the listener
	 */
	public void addCompositeViewerModelListener(CompositeViewerModelListener listener) {
		modelListeners.add(listener);
	}

	/**
	 * Removes a CompositeViewerModelListener that was being notified when model changes occur
	 * @param listener the listener
	 */
	public void removeCompositeViewerModelListener(CompositeViewerModelListener listener) {
		modelListeners.remove(listener);
	}

	/**
	 * Called whenever the composite's non-component information changes.  For example, the name,
	 * or description change.
	 */
	protected void compositeInfoChanged() {
		notify(modelListeners, CompositeViewerModelListener::compositeInfoChanged);
	}

	/**
	 * Called whenever the composite's component data changes.
	 */
	protected void componentDataChanged() {
		notify(modelListeners, CompositeViewerModelListener::componentDataChanged);
	}

	/**
	 * Determines the full path name for the composite data type based on the original composite
	 * and original category.
	 * @return the full path name
	 */
	public final DataTypePath getOriginalDataTypePath() {
		return originalDataTypePath;
	}

	@Override
	public void categoryAdded(DataTypeManager dtm, CategoryPath path) {
		// new categories don't matter
	}

	@Override
	public void sourceArchiveAdded(DataTypeManager dataTypeManager, SourceArchive dataTypeSource) {
		// don't care
	}

	@Override
	public void sourceArchiveChanged(DataTypeManager dataTypeManager,
			SourceArchive dataTypeSource) {
		// don't care
	}

	@Override
	public void categoryRemoved(DataTypeManager dtm, CategoryPath path) {
		if (dtm != originalDTM) {
			return; // Different DTM than the one for this data type.
		}
		if (originalDataTypePath.isAncestor(path)) {
			String msg = "\"" + originalDataTypePath.getDataTypeName() + "\" had its category \"" +
				path.getPath() + "\" removed.";
			setStatus(msg, true);
		}
		else if (hasSubDtInCategory(viewComposite, path.getPath())) {
			String msg = "The category \"" + path.getPath() +
				"\" was removed, which contained a sub-component of \"" +
				originalDataTypePath.getDataTypeName() + "\".";
			setStatus(msg, true);
		}
	}

	private void changeOriginalDataTypeCategory(CategoryPath oldPath, CategoryPath newPath) {
		String originalCategory = originalDataTypePath.getCategoryPath().getPath();
		String suffix = originalCategory.substring(oldPath.getPath().length());
		originalDataTypePath =
			new DataTypePath(newPath + suffix, originalDataTypePath.getDataTypeName());
	}

	@Override
	public void categoryRenamed(DataTypeManager dtm, CategoryPath oldPath, CategoryPath newPath) {
		if (dtm != originalDTM) {
			return; // Different DTM than the one for this data type.
		}
		if (!viewDTM.containsCategory(oldPath)) {
			return;
		}
		Category oldCat = viewDTM.getCategory(oldPath);
		viewDTM.withTransaction("Category Renamed", () -> {
			viewDTM.clearUndoOnChange();
			try {
				oldCat.setName(newPath.getName());
			}
			catch (DuplicateNameException e) {
				Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			}
			catch (InvalidNameException e) {
				Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			}
			if (originalDataTypePath.isAncestor(oldPath)) {
				changeOriginalDataTypeCategory(oldPath, newPath);
			}
		});

		compositeInfoChanged();
	}

	@Override
	public void categoryMoved(DataTypeManager dtm, CategoryPath oldPath, CategoryPath newPath) {
		if (dtm != originalDTM) {
			return; // Different DTM than the one for this data type.
		}
		if (!viewDTM.containsCategory(oldPath)) {
			return;
		}
		Category oldCat = viewDTM.getCategory(oldPath);
		if (oldCat == null) {
			return;
		}
		CategoryPath parent = newPath.getParent();
		viewDTM.withTransaction("Category Moved", () -> {
			viewDTM.clearUndoOnChange();
			viewDTM.createCategory(parent);
			Category newCat = viewDTM.getCategory(parent);
			try {
				newCat.moveCategory(oldCat, TaskMonitor.DUMMY);
			}
			catch (DuplicateNameException e) {
				Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			}
		});
		if (originalDataTypePath.isAncestor(oldPath)) {
			changeOriginalDataTypeCategory(oldPath, newPath);
		}
		compositeInfoChanged();
	}

	@Override
	public void dataTypeAdded(DataTypeManager dtm, DataTypePath path) {
		// Adding a new data type doesn't affect this one?
	}

	@Override
	public void favoritesChanged(DataTypeManager dtm, DataTypePath path, boolean isFavorite) {
		// Don't care.
	}

	@Override
	public void programArchitectureChanged(DataTypeManager dataTypeManager) {
		// don't care
	}

	@Override
	public abstract void restored(DataTypeManager dataTypeManager);

//=================================================================================================
// Helper methods for CategoryChangeListener methods.
//=================================================================================================

	/**
	 * Determines whether the indicated composite data type has any sub-components that are within
	 * the indicated category or one of its sub-categories.
	 * @param parentDt the composite data type
	 * @param catPath the category's path
	 * @return true if a sub-component is in the indicated category
	 */
	boolean hasSubDtInCategory(Composite parentDt, String catPath) {
		DataTypeComponent components[] = parentDt.getDefinedComponents();
		// FUTURE Add a structure to keep track of which composites were searched so they aren't
		// searched multiple times.
		for (DataTypeComponent component : components) {
			DataType subDt = component.getDataType();
			String subCatPath = subDt.getCategoryPath().getPath();
			if (subCatPath.startsWith(catPath)) {
				return true;
			}
			else if (subDt instanceof Composite) {
				if (hasSubDtInCategory((Composite) subDt, catPath)) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Determines whether the indicated composite data type has any sub-components that are the
	 * indicated data type.
	 * @param parentDt the composite data type
	 * @param dtPath the data type to be detected
	 * @return true if the composite data type has the data type as a sub-component
	 */
	protected boolean hasSubDt(Composite parentDt, DataTypePath dtPath) {
		DataTypeComponent components[] = parentDt.getDefinedComponents();
		for (DataTypeComponent component : components) {
			DataType subDt = component.getDataType();

			String subDtPath = subDt.getPathName();
			if (subDtPath.equals(dtPath.getPath())) {
				return true;
			}
			else if (subDt instanceof Composite) {
				if (hasSubDt((Composite) subDt, dtPath)) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Returns a copy of the model's current field selection
	 * @return the selection
	 */
	public FieldSelection getSelection() {
		return new FieldSelection(this.selection);
	}

	/**
	 * Returns true if the GUI has a table row selected
	 * @return true if there is a selection
	 */
	public boolean hasSelection() {
		return (selection.getNumRanges() > 0);
	}

	/**
	 * Returns true if the GUI has a component row selected
	 * @return true if there is a selection
	 */
	public boolean hasComponentSelection() {
		return ((selection.getNumRanges() > 0) &&
			(selection.getFieldRange(0).getStart().getIndex().intValue() < getNumComponents()));
	}

	/**
	 * Returns the number of rows currently selected.
	 * 
	 * <p>Note: In unlocked mode this can include the additional blank line.
	 * 
	 * @return the selected row count
	 */
	public int getNumSelectedRows() {
		int count = 0;
		for (FieldRange range : this.selection) {
			int endIndex = range.getEnd().getIndex().intValue();
			int startIndex = range.getStart().getIndex().intValue();
			count += endIndex - startIndex;
		}
		return count;
	}

	/**
	 * Returns the number of component rows currently selected.
	 * 
	 * <p>Note: This only includes rows that are actually components.
	 * 
	 * @return the selected row count
	 */
	public int getNumSelectedComponentRows() {
		int numComponents = getNumComponents();
		int count = 0;
		for (FieldRange range : this.selection) {
			int endIndex = Math.min(range.getEnd().getIndex().intValue(), numComponents);
			int startIndex = range.getStart().getIndex().intValue();
			int rangeCount = endIndex - startIndex;
			if (rangeCount > 0) {
				count += rangeCount;
			}
		}
		return count;
	}

	/**
	 * Returns true if the component list selection is contiguous.
	 * @return true if contiguous
	 */
	public boolean isContiguousSelection() {
		return (selection.getNumRanges() == 1);
	}

	/**
	 * Returns true if the component list selection is a single component.
	 * @return true if the component list selection is a single component
	 */
	public boolean isSingleComponentRowSelection() {
		if (!isSingleRowSelection()) {
			return false;
		}
		FieldRange range = selection.getFieldRange(0);
		int rowIndex = range.getStart().getIndex().intValue();
		return getComponent(rowIndex) != null;
	}

	/**
	 * Returns true if the selection is a single row.
	 * @return true if the selection is a single row
	 */
	protected boolean isSingleRowSelection() {
		if (selection.getNumRanges() != 1) {
			return false;
		}
		FieldRange range = selection.getFieldRange(0);
		return (range.getStart().getIndex().intValue() == range.getEnd().getIndex().intValue() - 1);
	}

	/**
	 * Returns true if the list selection is contiguous and only contains component rows.
	 * @return true if the list selection is contiguous and only contains component rows
	 */
	protected boolean isContiguousComponentSelection() {
		return ((selection.getNumRanges() == 1) &&
			selection.getFieldRange(0).getStart().getIndex().intValue() < getNumComponents());
	}

	/**
	 * Get an array of the indices for all the selected rows.
	 * @return the selected rows
	 */
	protected int[] getSelectedRows() {
		ArrayList<Integer> list = new ArrayList<>();
		for (FieldRange range : this.selection) {
			int endIndex = range.getEnd().getIndex().intValue();
			int startIndex = range.getStart().getIndex().intValue();
			for (int i = startIndex; i < endIndex; i++) {
				list.add(i);
			}
		}
		return list.stream().mapToInt(Integer::intValue).toArray();
	}

	/**
	 * Get an array of the row indices for all the selected components.
	 * @return the selected rows
	 */
	protected int[] getSelectedComponentRows() {
		ArrayList<Integer> list = new ArrayList<>();
		int numComponents = getNumComponents();
		for (FieldRange range : this.selection) {
			int endIndex = Math.min(range.getEnd().getIndex().intValue(), numComponents);
			int startIndex = range.getStart().getIndex().intValue();
			for (int i = startIndex; i < endIndex; i++) {
				list.add(i);
			}
		}
		return list.stream().mapToInt(Integer::intValue).toArray();
	}

	/**
	 * Returns the selection range containing the specified row index if there is one that contains
	 * it. Otherwise, returns null.
	 *
	 * @param rowIndex the row index
	 * @return the range or null
	 */
	protected FieldRange getSelectedRangeContaining(int rowIndex) {
		FieldRange fieldRange = null;
		if (selection.containsEntirely(BigInteger.valueOf(rowIndex))) {
			// Get the size of the selection range we are in.
			int numRanges = selection.getNumRanges();
			for (int i = 0; i < numRanges; i++) {
				FieldRange range = selection.getFieldRange(i);
				if ((range.getStart().getIndex().intValue() <= rowIndex) &&
					(rowIndex < range.getEnd().getIndex().intValue())) {
					fieldRange = range;
					break;
				}
			}
		}
		return fieldRange;
	}

	/**
	 * Gets the minimum row index that is selected or -1 if no index is selected.
	 * @return the index
	 */
	public int getMinIndexSelected() {
		if (!selection.isEmpty()) {
			FieldRange fieldRange = selection.getFieldRange(0);
			return fieldRange.getStart().getIndex().intValue();
		}
		return -1;
	}

	/**
	 * Saves the current selection in the structure components viewing area.
	 *
	 * @param rows the indices for the selected rows.
	 */
	protected void setSelection(int[] rows) {

		if (updatingSelection) {
			return;
		}
		FieldSelection tmpSelection = new FieldSelection();
		int numComponents = viewComposite.getNumComponents();
		for (int row2 : rows) {
			// Only add valid component rows (i.e. don't include blank last line)
			if (row2 < numComponents) {
				tmpSelection.addRange(row2, row2 + 1);
			}
		}
		if (this.selection.equals(tmpSelection)) {
			return;
		}
		this.selection = tmpSelection;
		adjustCurrentRow();
		selectionChanged();
	}

	/**
	 * Sets the model's current selection to the indicated selection.  If the selection is empty,
	 * it gets adjusted to the empty last line when in unlocked mode.
	 * @param selection the new selection
	 */
	protected void setSelection(FieldSelection selection) {
		if (updatingSelection) {
			return;
		}
		if (this.selection.equals(selection)) {
			return;
		}
		this.selection.clear();
		int numRanges = selection.getNumRanges();
		for (int i = 0; i < numRanges; i++) {
			FieldRange range = selection.getFieldRange(i);
			this.selection.addRange(range.getStart().getIndex(), range.getEnd().getIndex());
		}
		adjustCurrentRow();
		selectionChanged();
	}

	protected void adjustSelection(int rowIndex, int adjustment) {
		FieldSelection newSelection = new FieldSelection();
		int num = selection.getNumRanges();
		for (int i = 0; i < num; i++) {
			FieldRange range = selection.getFieldRange(i);
			int last = range.getEnd().getIndex().intValue() - 1;
			if (last < rowIndex) {
				newSelection.addRange(range.getStart().getIndex(), range.getEnd().getIndex());
			}
			else if (range.getStart().getIndex().intValue() >= rowIndex) {
				newSelection.addRange(range.getStart().getIndex().intValue() + adjustment,
					range.getEnd().getIndex().intValue() + adjustment);
			}
			else {
				newSelection.addRange(range.getStart().getIndex().intValue(), rowIndex);
				newSelection.addRange(rowIndex + adjustment,
					range.getEnd().getIndex().intValue() + adjustment);
			}
		}
		selection = newSelection;
	}

	protected void updatingSelection(Callback c) {

		swing(() -> {
			boolean tmpUpdatingSelection = updatingSelection;
			try {
				updatingSelection = true;
				c.call();
			}
			finally {
				updatingSelection = tmpUpdatingSelection;
			}
		});
	}

	protected void selectionChanged() {

		updatingSelection(() -> {
			for (CompositeViewerModelListener listener : modelListeners) {
				listener.selectionChanged();
			}
			provider.contextChanged();
		});
	}

	/**
	 * Convenience method to run the given task on the swing thread.
	 * @param r the runnable
	 */
	protected void swing(Runnable r) {
		Swing.runIfSwingOrRunLater(r);
	}

	/**
	 * A notify method to take the listens to notify, along with the method that should be called
	 * on each listener.
	 * 
	 * @param <T> the type of the listener
	 * @param listeners the listeners
	 * @param method the method to call
	 */
	protected <T> void notify(List<T> listeners, Consumer<T> method) {
		swing(() -> {
			for (T listener : listeners) {
				method.accept(listener);
			}
		});
	}

	/**
	 * Sets whether or not the editor displays numeric values in hexadecimal.
	 * @param showHex true means show in hexadecimal. false means show in decimal
	 */
	public void displayNumbersInHex(boolean showHex) {
		if (this.showHexNumbers != showHex) {
			this.showHexNumbers = showHex;
			this.fireTableDataChanged();
			this.compositeInfoChanged();
		}
	}

	/**
	 * Returns whether or not the editor is displaying numbers in hex
	 * @return true if hex
	 */
	public boolean isShowingNumbersInHex() {
		return showHexNumbers;
	}

	public static String getHexString(int offset, boolean showPrefix) {
		String prefix = showPrefix ? "0x" : "";
		return ((offset >= 0) ? (prefix + Integer.toHexString(offset))
				: ("-" + prefix + Integer.toHexString(-offset)));
	}

	/**
	 * If there is a selection, this changes the row to the minimum row selected.
	 */
	protected void adjustCurrentRow() {
		int currentRow = -1;
		if (this.selection.getNumRanges() > 0) {
			currentRow = this.selection.getFieldRange(0).getStart().getIndex().intValue();
		}
		setRow(currentRow);
	}

	protected long getCompositeID() {
		return originalCompositeId;
	}

	/**
	 * Determine if {@link DataType#getAlignedLength() aligned-length} components should be used. 
	 * @return true if aligned-length components should be used, else false
	 */
	protected boolean usesAlignedLengthComponents() {
		return viewComposite.isPackingEnabled();
	}

}
