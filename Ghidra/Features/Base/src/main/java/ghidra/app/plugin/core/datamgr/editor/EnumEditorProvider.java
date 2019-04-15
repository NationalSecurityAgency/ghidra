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
package ghidra.app.plugin.core.datamgr.editor;

import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.util.*;

import javax.swing.ImageIcon;
import javax.swing.JComponent;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.table.TableCellEditor;

import org.apache.commons.lang3.StringUtils;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.*;
import docking.widgets.OptionDialog;
import ghidra.app.plugin.core.compositeeditor.EditorListener;
import ghidra.app.plugin.core.compositeeditor.EditorProvider;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.util.*;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.DuplicateNameException;
import resources.ResourceManager;
import util.CollectionUtils;

/**
 * Editor for an Enum data type.
 */
public class EnumEditorProvider extends ComponentProviderAdapter
		implements ChangeListener, EditorProvider {

	static final ImageIcon EDITOR_ICON = ResourceManager.loadImage("images/enum.png");
	private final static ImageIcon APPLY_ICON = ResourceManager.loadImage("images/disk.png");
	private final static ImageIcon ADD_ICON = ResourceManager.loadImage("images/Plus.png");
	private final static ImageIcon DELETE_ICON =
		ResourceManager.loadImage("images/edit-delete.png");
	private final static String HELP_TOPIC = "DataTypeEditors";

	private final static int CANCEL = 0;
	private final static int SAVE = 1;
	private final static int NO_SAVE = 2;
	private final static int ERROR = 3;

	private DataTypeManagerPlugin plugin;
	private EnumEditorPanel editorPanel;
	private WeakSet<EditorListener> listeners;
	private MyDataTypeManagerChangeListener catListener;

	private DockingAction addAction;
	private DockingAction deleteAction;
	private DockingAction applyAction;

	private DataTypeManager dataTypeManager;
	private String originalEnumName;
	private CategoryPath originalCategoryPath;
	private Enum originalEnum;
	private long originalEnumID = -1;

	/**
	 * Construct a new enum editor provider. 
	 * @param plugin owner of this provider
	 * @param enumDT enum data type
	 */
	public EnumEditorProvider(DataTypeManagerPlugin plugin, Enum enumDT) {
		super(plugin.getTool(), "Enum Editor", plugin.getName());
		this.plugin = plugin;
		DataTypeManager enumDTM = enumDT.getDataTypeManager();
		if (enumDTM == null) {
			throw new IllegalArgumentException(
				"Datatype " + enumDT.getName() + " doesn't have a data type manager specified.");
		}
		CategoryPath categoryPath = enumDT.getCategoryPath();
		Category category = enumDTM.getCategory(categoryPath);
		if (category == null) {
			throw new IllegalArgumentException(
				"Datatype " + enumDT.getName() + " doesn't have a category specified.");
		}
		originalCategoryPath = categoryPath;
		originalEnum = enumDT;
		originalEnumName = enumDT.getDisplayName();
		dataTypeManager = enumDTM;

		setIcon(EDITOR_ICON);
		setHelpLocation(new HelpLocation(HELP_TOPIC, "EnumEditor"));

		catListener = new MyDataTypeManagerChangeListener();
		dataTypeManager.addDataTypeManagerListener(catListener);

		if (category.getDataType(originalEnumName) != null) {
			originalEnumID = dataTypeManager.getID(enumDT);
		}

		editorPanel = new EnumEditorPanel((EnumDataType) enumDT.copy(dataTypeManager), this);

		updateTitle(enumDT);
		tool.addComponentProvider(this, true);
		createActions();
		listeners = WeakDataStructureFactory.createSingleThreadAccessWeakSet();

		editorPanel.getTable().getSelectionModel().addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}
			setActionsEnabled();
		});
	}

	@Override
	public String getWindowSubMenuName() {
		return getName();
	}

	@Override
	public void closeComponent() {
		int result = saveChangesForCloseEvent(true);
		if (result == SAVE || result == NO_SAVE) {
			dispose();
		}
	}

	@Override
	public JComponent getComponent() {
		return editorPanel;
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		return new ActionContext(this, editorPanel.getTable());
	}

	@Override
	public void stateChanged(ChangeEvent e) {
		if (applyAction == null) {
			return; // we will get this call during initialization
		}
		applyAction.setEnabled(hasChanges());
	}

	@Override
	public void addEditorListener(EditorListener listener) {
		listeners.add(listener);
	}

	@Override
	public boolean checkForSave(boolean allowCancel) {
		int result = saveChangesForCloseEvent(allowCancel);
		if (result == CANCEL || result == ERROR) {
			if (allowCancel) {
				return false;
			}
		}
		return true;
	}

	@Override
	public void dispose() {
		tool.showComponentProvider(this, false);
		tool.removeComponentProvider(this);
		editorPanel.dispose();
		for (EditorListener el : listeners) {
			el.closed(this);
		}
		dataTypeManager.removeDataTypeManagerListener(catListener);
	}

	@Override
	public ComponentProvider getComponentProvider() {
		return this;
	}

	@Override
	public DataTypePath getDtPath() {
		return new DataTypePath(originalCategoryPath, originalEnumName);
	}

	@Override
	public boolean isEditing(DataTypePath dtPath) {
		return getDtPath().equals(dtPath);
	}

	@Override
	public boolean needsSave() {
		return editorPanel.needsSave();
	}

	@Override
	public void domainObjectRestored(DataTypeManagerDomainObject domainObject) {

		if (originalEnumID == -1) {
			return;
		}

		Enum enuum = (Enum) dataTypeManager.getDataType(originalEnumID);
		if (enuum != null) {
			EnumDataType dt = (EnumDataType) enuum.copy(dataTypeManager);
			originalEnumName = dt.getDisplayName();
			updateTitle(dt);
			Category category = dataTypeManager.getCategory(enuum.getCategoryPath());
			originalCategoryPath = category.getCategoryPath();
			editorPanel.domainObjectRestored(domainObject, dt);
		}
		tool.setStatusInfo("");
	}

	@Override
	public boolean isTransient() {
		return true;
	}

	@Override
	public void show() {
		tool.showComponentProvider(this, true);
	}

	void setStatusMessage(String msg) {
		tool.setStatusInfo(msg);
	}

	String getCategoryText() {
		return dataTypeManager.getName() + originalCategoryPath;
	}

	@Override
	public DataTypeManager getDataTypeManager() {
		return dataTypeManager;
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private void updateTitle(DataType dataType) {
		setTitle(getName() + " - " + getProviderSubTitle(dataType));
		setTabText(dataType.getName());
	}

	private String getProviderSubTitle(DataType dataType) {
		String dtmName;
		DataTypeManager dtm = dataTypeManager;
		if (dtm == null) {
			return dataType.getDisplayName();
		}
		if (dtm instanceof ProgramBasedDataTypeManager) {
			ProgramBasedDataTypeManager programDtm = (ProgramBasedDataTypeManager) dtm;
			dtmName = programDtm.getProgram().getDomainFile().getName();
		}
		else {
			dtmName = dtm.getName();
		}
		return dataType.getDisplayName() + " (" + dtmName + ")";
	}

	private void createActions() {
		addAction = new EnumPluginAction("Add Enum Value", e -> editorPanel.addEntry());
		addAction.setEnabled(true);
		String editGroup = "Edit";
		addAction.setPopupMenuData(new MenuData(new String[] { "Add" }, ADD_ICON, editGroup));
		addAction.setToolBarData(new ToolBarData(ADD_ICON, editGroup));
		addAction.setDescription("Add a new enum entry");

		deleteAction =
			new EnumPluginAction("Delete Enum Value", e -> editorPanel.deleteSelectedEntries());
		deleteAction.setEnabled(false);
		deleteAction.setPopupMenuData(
			new MenuData(new String[] { "Delete" }, DELETE_ICON, editGroup));
		deleteAction.setToolBarData(new ToolBarData(DELETE_ICON, editGroup));
		deleteAction.setDescription("Delete the selected enum entries");

		applyAction = new EnumPluginAction("Apply Enum Changes", e -> applyChanges());
		applyAction.setEnabled(false);
		applyAction.setToolBarData(new ToolBarData(APPLY_ICON, "ApplyChanges"));
		applyAction.setDescription("Apply changes to Enum");

		tool.addLocalAction(this, applyAction);
		tool.addLocalAction(this, addAction);
		tool.addLocalAction(this, deleteAction);
	}

	private boolean applyChanges() {

		setStatusMessage("");
		TableCellEditor editor = editorPanel.getTable().getCellEditor();
		if (editor != null) {
			editor.stopCellEditing();
		}

		Enum editedEnum = editorPanel.getEnum();
		if (editedEnum.getCount() == 0) {
			setStatusMessage("Empty enum is not allowed");
			return false;
		}
		int txID = startTransaction();

		try {
			DataTypeManager dtm = editedEnum.getDataTypeManager();
			boolean userSaved = resolveEquateConflicts(editedEnum, dtm);
			if (!userSaved) {
				return false;
			}

			Enum newEnuum = (Enum) dataTypeManager.resolve(originalEnum, null);

			applyName(newEnuum);
			applyDescription(newEnuum);
			newEnuum.replaceWith(editedEnum);

			originalEnum = newEnuum;
			editorPanel.setEnum((EnumDataType) newEnuum.copy(dataTypeManager));
			applyAction.setEnabled(hasChanges());
		}
		finally {
			endTransaction(txID);
		}
		return true;
	}

	/**
	 * Checks to see if the new changes to the enum will affect equates based off of it.
	 * @param editedEnum the enum to check for conflicts with
	 * @param dtm the data type manager that this enum lies within
	 * @return true if the enum should save its changes; otherwise, false
	 */
	private boolean resolveEquateConflicts(Enum editedEnum, DataTypeManager dtm) {

		Program program = plugin.getProgram();
		if (program == null) {
			// No open program; data type not from the program archive.
			return true;
		}

		EquateTable et = program.getEquateTable();
		Set<String> oldFieldConflicts = new HashSet<>();
		Set<String> conflictingEquates = new HashSet<>();

		for (Equate eq : CollectionUtils.asIterable(et.getEquates())) {
			if (eq.isEnumBased() && originalEnum.getUniversalID().equals(eq.getEnumUUID()) &&
				editedEnum.getName(eq.getValue()) == null) {
				oldFieldConflicts.add(originalEnum.getName(eq.getValue()));
				conflictingEquates.add(eq.getName());
			}
		}
		if (conflictingEquates.isEmpty()) {
			return true;
		}
		switch (showOptionDialog(editedEnum, oldFieldConflicts)) {
			case OptionDialog.OPTION_ONE:
				removeEquates(et, conflictingEquates);
			case OptionDialog.OPTION_TWO:
				return true;
			case OptionDialog.CANCEL_OPTION:
			default:
				return false;
		}
	}

	private void removeEquates(EquateTable et, Set<String> equatesForDelete) {
		for (String name : equatesForDelete) {
			et.removeEquate(name);
		}
	}

	private int showOptionDialog(Enum editedEnoom, Set<String> oldNameFields) {
		StringBuilder msg = new StringBuilder(
			"<html>If you save this Enum with the <font color=#ff0000>new value(s)</font>" +
				" listed below,<br> it will invalidate equates created with the old value(s).<br>");
		msg.append("<ul>");
		for (String field : oldNameFields) {
			String newVal;
			try {
				newVal = "0x" + Long.toHexString(editedEnoom.getValue(field));
			}
			catch (NoSuchElementException e) {
				// Happens if a field is deleted or there is a name AND value change.
				newVal = "Missing";
			}
			msg.append(String.format("<li>%s: 0x%s \u2192 <font color=#ff0000>%s</font></li>",
				HTMLUtilities.escapeHTML(field), Long.toHexString(originalEnum.getValue(field)),
				newVal));
		}
		msg.append("</ul>");
		msg.append(
			"Invalidated equates can be automatically removed now or<br>managed later from the <i><b>Equates Table</i></b> window.");
		msg.append("</html>");
		int choice = OptionDialog.showOptionDialog(editorPanel, "Equate Conflicts", msg.toString(),
			"Save and remove", "Save", OptionDialog.ERROR_MESSAGE);
		return choice;
	}

	private void applyDescription(Enum newEnuum) {
		String editorDescription = editorPanel.getDescription();
		String originalDescription = newEnuum.getDescription();
		if (editorDescription != null) {
			editorDescription = editorDescription.trim();
			if (!editorDescription.equals(originalDescription)) {
				newEnuum.setDescription(editorDescription);
			}
		}
		else if (originalDescription != null) {
			newEnuum.setDescription(null);
		}
	}

	private void applyName(Enum newEnuum) {
		String editorName = editorPanel.getEnumName();
		if (originalEnumName.equals(editorName)) {
			return; // nothing to do
		}

		if (StringUtils.isBlank(editorName)) {
			Msg.showError(this, editorPanel, "Invalid Name", "Name cannot be empty.");
			return;
		}

		try {
			newEnuum.setName(editorName);
			originalEnumName = editorName;
			updateTitle(newEnuum);
		}
		catch (InvalidNameException e) {
			Msg.showError(this, editorPanel, "Invalid Name", "Name contains invalid characters.");
		}
		catch (DuplicateNameException e) {
			Msg.showError(this, editorPanel, "Duplicate Name", editorName + " already exists.");
		}
	}

	private void setActionsEnabled() {
		deleteAction.setEnabled(false);
		int[] rows = editorPanel.getSelectedRows();
		if (rows.length > 0) {
			deleteAction.setEnabled(true);
		}
	}

	private int startTransaction() {
		return dataTypeManager.startTransaction("Edit Enum");
	}

	private void endTransaction(int transID) {
		dataTypeManager.endTransaction(transID, true);
	}

	/**
	 * Prompts the user if the editor has unsaved changes. Saves the changes if
	 * the user indicates to do so.
	 * @return CANCEL (0) if the user canceled; 
	 *   SAVE (1) if the user saved changes; 
	 *   NO_SAVE (2) if the user did not save changes or no save was required; 
	 *   ERROR (3) if there was an error when the changes were applied.
	 */
	private int saveChangesForCloseEvent(boolean allowCancel) {
		// Check for changes and prompt user to check if saving them.
		if (hasChanges()) {
			String question = "The Enum Editor is closing.\n" + "Save the changes to " +
				editorPanel.getEnum().getDisplayName() + "?";
			String title = "Save Enum Editor Changes?";
			int response;
			if (allowCancel) {
				response = OptionDialog.showYesNoCancelDialog(editorPanel, title, question);
			}
			else {
				response = OptionDialog.showYesNoDialog(editorPanel, title, question);
			}
			if (response == OptionDialog.OPTION_ONE) {
				// YES selected.
				if (!applyChanges()) {
					return ERROR;
				}
			}
			return response;
		}
		return NO_SAVE; // no save required, or No selected
	}

	public boolean hasChanges() {
		return editorPanel.needsSave();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class MyDataTypeManagerChangeListener extends DataTypeManagerChangeListenerAdapter {

		@Override
		public void categoryMoved(DataTypeManager dtm, CategoryPath oldPath, CategoryPath newPath) {

			if (!originalCategoryPath.equals(oldPath)) {
				return;
			}

			Category newCategory = dtm.getCategory(newPath);
			if (newCategory == null) {
				// this can happen when a category is somehow created and then deleted before the
				// events have gone out
				return;
			}

			originalCategoryPath = newCategory.getCategoryPath();
			dataTypeManager = dtm;
			editorPanel.updateCategoryField(getCategoryText());
		}

		@Override
		public void categoryRenamed(DataTypeManager dtm, CategoryPath oldPath,
				CategoryPath newPath) {

			if (!originalCategoryPath.equals(oldPath)) {
				return;
			}

			Category newCategory = dtm.getCategory(newPath);
			if (newCategory == null) {
				// this can happen when a category is somehow created and then deleted before the
				// events have gone out
				return;
			}

			originalCategoryPath = newCategory.getCategoryPath();
			dataTypeManager = dtm;
			editorPanel.updateCategoryField(getCategoryText());
		}

		@Override
		public void categoryRemoved(DataTypeManager dtm, CategoryPath path) {
			// should never get this callback, as we should first have gotten a 
			// dataTypeRemoved(), which will dispose this editor
		}

		@Override
		public void dataTypeChanged(DataTypeManager dtm, DataTypePath path) {
			if (!isMyCategory(path)) {
				return;
			}

			DataType currentDataType = getCurrentDataType();
			if (!isMyDataType(currentDataType, dtm, path)) {
				return;
			}
			if (!hasChanges()) {
				editorPanel.enumChanged((EnumDataType) ((Enum) currentDataType).copy(dtm));
			}
			applyAction.setEnabled(hasChanges());
		}

		@Override
		public void dataTypeMoved(DataTypeManager dtm, DataTypePath oldPath, DataTypePath newPath) {
			if (!isMyCategory(oldPath)) {
				return;
			}

			DataType currentDataType = getCurrentDataType();
			if (!isMyDataType(currentDataType, dtm, newPath)) {
				return;
			}

			// at this point, the changed data type might not be ours, but update anyway
			CategoryPath currentCategoryPath = currentDataType.getCategoryPath();
			Category category = dtm.getCategory(currentCategoryPath);
			originalCategoryPath = category.getCategoryPath();
			dataTypeManager = dtm;
			editorPanel.updateCategoryField(getCategoryText());
		}

		@Override
		public void dataTypeRenamed(DataTypeManager dtm, DataTypePath oldPath,
				DataTypePath newPath) {
			if (!isMyCategory(oldPath)) {
				return;
			}

			DataType currentDataType = getCurrentDataType();
			if (!isMyDataType(currentDataType, dtm, newPath)) {
				return;
			}

			String newName = currentDataType.getDisplayName();
			String nameInTextField = editorPanel.getEnumName();
			if (originalEnumName.equals(nameInTextField)) {
				// the name hasn't changed--just update it
				editorPanel.updateNameField(newName);
			}

			originalEnumName = newName;
			updateTitle(currentDataType);
		}

		@Override
		public void dataTypeRemoved(DataTypeManager dtm, DataTypePath path) {

			if (!isMyCategory(path)) {
				return;
			}

			DataType currentDataType = getCurrentDataType();
			if (currentDataType != null) {
				// the data type is still around--must have been a different data type
				return;
			}

			Msg.showWarn(getClass(), editorPanel, "Enum Data Type Removed",
				path + " was removed from data type manager " + dtm.getName() +
					".\nEdit session will be terminated.");
			dispose();
		}

		@Override
		public void dataTypeReplaced(DataTypeManager dtm, DataTypePath oldPath,
				DataTypePath newPath, DataType newDataType) {

			if (!isMyCategory(oldPath)) {
				return;
			}

			DataType currentDataType = getCurrentDataType();
			if (currentDataType != null) {
				// the data type is still around--must have been a different data type
				return;
			}

			Msg.showWarn(getClass(), editorPanel, "Enum Data Type Replaced",
				oldPath + " was replaced in data type manager " + dtm.getName() +
					".\nEdit session will be terminated.");
			dispose();
		}

		private boolean isMyCategory(DataTypePath path) {
			CategoryPath parentPath = path.getCategoryPath();
			return parentPath.equals(originalCategoryPath);
		}

		private DataType getCurrentDataType() {
			return dataTypeManager.getDataType(originalEnumID);
		}

		private boolean isMyDataType(DataType myDataType, DataTypeManager dtm,
				DataTypePath otherPath) {
			if (myDataType == null) {
				return false; // must have been deleted and we have not yet processed the event
			}

			DataType dataType = dtm.getDataType(otherPath);
			if (dataType == null) {
				// 
				// Unusual Code Alert!: 
				// Must have been deleted and we have not yet processed the event...return true
				// here to signal that the types are the same so that clients will continue the
				// updating process.  The types may not really be the same, but the fallout is 
				// only that there will be more updating than is necessary.
				//
				return true;
			}

			return myDataType == dataType;
		}
	}

	private class EnumPluginAction extends DockingAction {
		private final ActionListener listener;

		EnumPluginAction(String name, ActionListener listener) {
			super(name, plugin.getName());
			this.listener = listener;
			setHelpLocation(new HelpLocation(HELP_TOPIC, name));
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if (!isAllowedContext(context)) {
				return false;
			}
			return super.isEnabledForContext(context);
		}

		private boolean isAllowedContext(ActionContext context) {
			return (editorPanel.getTableClass().isInstance(context.getContextObject()));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (listener != null) {
				listener.actionPerformed(null);
			}
		}
	}
}
