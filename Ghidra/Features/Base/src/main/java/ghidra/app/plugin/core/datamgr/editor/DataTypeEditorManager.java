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

import java.util.ArrayList;
import java.util.List;

import docking.ComponentProvider;
import docking.actions.DockingToolActions;
import docking.actions.SharedDockingActionPlaceholder;
import ghidra.app.plugin.core.compositeeditor.*;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.function.AbstractEditFunctionSignatureDialog;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Program;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;

/**
 * Manages program and archive data type editors.
 */
public class DataTypeEditorManager
		implements EditorListener, StructureEditorOptionManager, UnionEditorOptionManager {

	private ArrayList<EditorProvider> editorList;
	private EditorOptionManager editorOptionMgr; // manages editor tool options
	private DataTypeManagerPlugin plugin;

	/**
	 * Constructs a manager for data type editors.
	 * @param plugin the plugin that owns this editor manager
	 */
	public DataTypeEditorManager(DataTypeManagerPlugin plugin) {
		this.plugin = plugin;
		initialize();
	}

	/**
	 * Dismisses all open editors without prompting to save any changes.
	 * Performs any other cleanup necessary for this manager.
	 */
	public void dispose() {
		// Close all editors without checking for changes.
		dismissEditors(null);
		editorOptionMgr.dispose();
	}

	/**
	 * Gets the location of the help for editing the specified data type.
	 * @param dataType the data type to be edited.
	 * @return the help location for editing the data type.
	 */
	public HelpLocation getEditorHelpLocation(DataType dataType) {
		if (dataType instanceof Enum) {
			return new HelpLocation("DataTypeEditors", "EnumEditor");
		}
		if ((dataType instanceof Union) || (dataType instanceof Structure)) {
			return new HelpLocation("DataTypeEditors", "Structure_Editor");
		}
		// default
		return new HelpLocation("DataTypeEditors", "Structure_Editor");
	}

	/**
	 * Determine if the indicated data type can be edited
	 * (i.e. it has an editor that this service knows how to invoke).
	 * @param dt data type to be edited
	 * @return true if this service can invoke an editor for changing the data type.
	 */
	public boolean isEditable(DataType dt) {
		if ((dt instanceof Enum) || (dt instanceof Union) || (dt instanceof Structure)) {
			return true;
		}
		return false;
	}

	/**
	 * Displays a data type editor for editing the indicated data type. If the data type is
	 * is already being edited then it is brought to the front. Otherwise, a new editor is created
	 * and displayed.
	 * @param dataType the data type to edit.
	 */
	public void edit(DataType dataType) {

		DataTypeManager dataTypeManager = dataType.getDataTypeManager();
		if (dataTypeManager == null) {
			throw new IllegalArgumentException(
				"Datatype " + dataType.getName() + " doesn't have a data type manager specified.");
		}

		EditorProvider editor = getEditor(dataType);
		if (editor != null) {
			ComponentProvider componentProvider = editor.getComponentProvider();
			plugin.getTool().showComponentProvider(componentProvider, true);
			componentProvider.toFront();
			return;
		}

		if (dataType instanceof Enum) {
			editor = new EnumEditorProvider(plugin, (Enum) dataType);
		}
		else if (dataType instanceof Union) {
			editor = new UnionEditorProvider(plugin, (Union) dataType, showUnionNumbersInHex());
		}
		else if (dataType instanceof Structure) {
			editor = new StructureEditorProvider(plugin, (Structure) dataType,
				showStructureNumbersInHex());
		}
		else if (dataType instanceof FunctionDefinition) {
			editFunctionSignature((FunctionDefinition) dataType);
		}
		if (editor == null) {
			return;
		}
		editor.addEditorListener(this);
		editorList.add(editor);
	}

	private void installEditorActions() {

		registerAction(ApplyAction.ACTION_NAME);
		registerAction(InsertUndefinedAction.ACTION_NAME);
		registerAction(MoveUpAction.ACTION_NAME);
		registerAction(MoveDownAction.ACTION_NAME);
		registerAction(ClearAction.ACTION_NAME);
		registerAction(DuplicateAction.ACTION_NAME);
		registerAction(DuplicateMultipleAction.ACTION_NAME);
		registerAction(DeleteAction.ACTION_NAME);
		registerAction(PointerAction.ACTION_NAME);
		registerAction(ArrayAction.ACTION_NAME);
		registerAction(FindReferencesToField.ACTION_NAME);
		registerAction(UnpackageAction.ACTION_NAME);
		registerAction(EditComponentAction.ACTION_NAME);
		registerAction(EditFieldAction.ACTION_NAME);
		registerAction(HexNumbersAction.ACTION_NAME);
		registerAction(CreateInternalStructureAction.ACTION_NAME);
		registerAction(ShowComponentPathAction.ACTION_NAME);
		registerAction(AddBitFieldAction.ACTION_NAME);
		registerAction(EditBitFieldAction.ACTION_NAME);
	}

	private void registerAction(String name) {
		DockingToolActions toolActions = plugin.getTool().getToolActions();
		toolActions.registerSharedActionPlaceholder(new DtSharedActionPlaceholder(name));
	}

	/**
	 * Checks for editor changes that have not been saved to the data type and prompts the user to save
	 * them if necessary. It then closes the editor.
	 * @param editor the editor we want to close.
	 * @param allowCancel true indicates that the user can cancel the editor close when prompted
	 * for whether to save changes or not.
	 * @return true if the editor is closed.
	 */
	boolean closeEditor(EditorProvider editor, boolean allowCancel) {
		if (checkEditor(editor, allowCancel)) {
			dismissEditor(editor);
			return true;
		}
		return false;
	}

	/**
	 * Get a list of data type path names for data types that are currently being edited
	 * @return a list of data type path names for data types that are currently being edited.
	 */
	public List<DataTypePath> getEditsInProgress() {
		List<DataTypePath> paths = new ArrayList<>();
		for (EditorProvider editor : editorList) {
			paths.add(editor.getDtPath());
		}
		return paths;
	}

	/**
	 * Get the category for the data type being edited; the data type
	 * may be new and not yet added to the category
	 * @param dataTypePath the full path name of the data type that is being
	 * edited if it were written to the category for this editor.
	 * @return category associated with the data type or null.
	 */
	public Category getEditedDataTypeCategory(DataTypePath dataTypePath) {
		CategoryPath categoryPath = dataTypePath.getCategoryPath();
		for (EditorProvider editor : editorList) {
			if (dataTypePath.equals(editor.getDtPath())) {
				DataTypeManager dtMgr = editor.getDataTypeManager();
				if (dtMgr.containsCategory(categoryPath)) {
					return dtMgr.getCategory(categoryPath);
				}
			}
		}
		return null;
	}

	/**
	 * Determines whether this manager has any data type editor sessions in progress.
	 * @return true if there are any data type editors.
	 */
	public boolean isEditInProgress() {
		return editorList.size() > 0;
	}

	/**
	 * Check for any data types being edited for the given data
	 * type manager and closes those editors. An editor is associated with a data type
	 * manager based on the data type manager for the category where the edits will be saved.
	 * If dtMgr is null then all editors will be dismissed.
	 * @param dtMgr the data type manager whose editors are to be dismissed.
	 * If null, then dismiss all editors.
	 */
	public void dismissEditors(DataTypeManager dtMgr) {
		ArrayList<EditorProvider> list = new ArrayList<>();
		for (EditorProvider editor : editorList) {
			DataTypeManager editorDtm = editor.getDataTypeManager();
			if ((dtMgr == null) || (dtMgr == editorDtm)) {
				list.add(editor);
			}
		}
		for (EditorProvider element : list) {
			dismissEditor(element);
		}
	}

	/**
	 * Closes the data type editor for the indicated data type.
	 * @param editor the editor to close.
	 */
	void dismissEditor(EditorProvider editor) {
		if (editor != null) {
			editor.dispose();
		}
		editorList.remove(editor); // Should the remove happen here or via the EditorListener?
	}

	/**
	 * Check for data types being edited for the given data type manager and prompt the user to
	 * save any unsaved changes.
	 * If dtMgr is null then all editors will be checked.
	 * @param dtMgr the data type manager whose editors are to be checked for changes.
	 * If null, then check all editors for save.
	 * @param allowCancel true indicates that the user can cancel the editor close when prompted
	 * for whether to save changes or not.
	 * @return true if all editors were resolved and can close now; return
	 * false if the user canceled when prompted to save changes.
	 */
	public boolean checkEditors(DataTypeManager dtMgr, boolean allowCancel) {
		for (EditorProvider editor : editorList) {
			DataTypeManager editorDtm = editor.getDataTypeManager();
			if (dtMgr == null || dtMgr == editorDtm) {
				if (!checkEditor(editor, allowCancel)) {
					return false;
				}
			}
		}
		return true;
	}

	/**
	 * Determines if the indicated editor has unsaved changes.
	 * Prompts the user to save the changes.
	 * @param editor the editor to check.
	 * @param allowCancel true indicates that the user can cancel the editor close when prompted
	 * for whether to save changes or not.
	 * @return true when done checking or false if the user cancels.
	 */
	boolean checkEditor(EditorProvider editor, boolean allowCancel) {
		if (editor != null) {
			if (editor.needsSave()) {
				editor.show();
				if (!editor.checkForSave(allowCancel)) {
					return false;
				}
			}
		}
		return true;
	}

	/**
	 * Gets the manager for the data type editor options.
	 * @return the option manager
	 */
	EditorOptionManager getEditorOptionManager() {
		return editorOptionMgr;
	}

	/**
	 * Generate a unique data type name; Checks the data type manager for the indicated category
	 * to determine a unique name based on the specified base name. Also, checks the current
	 * edit sessions so we don't use a name already being edited.
	 * @param category the category where the data type will be saved after editing.
	 * @param baseName the base name of the data type
	 * @return the unique data type name.
	 */
	String getUniqueName(Category category, String baseName) {
		DataTypeManager dtm = category.getDataTypeManager();
		String uniqueName = dtm.getUniqueName(category.getCategoryPath(), baseName);
		int oneUpNumber = 0;
		int pos = uniqueName.lastIndexOf('_');
		if (pos > 0) {
			try {
				String numStr = uniqueName.substring(pos + 1);
				oneUpNumber = Integer.parseInt(numStr);
				baseName = uniqueName.substring(0, pos);
			}
			catch (NumberFormatException e) {
				// leave at 0
			}
		}

		while (nameExists(dtm, uniqueName)) {
			++oneUpNumber;
			uniqueName = baseName + "_" + oneUpNumber;
		}
		return uniqueName;
	}

	/**
	 * Determines if a data type, indicated by the path name, already exists in a data type manager.
	 * @param dtm the data type manager
	 * @param dtName data type path name
	 * @return true if the named data type exists.
	 */
	public boolean nameExists(DataTypeManager dtm, String dtName) {
		for (EditorProvider editor : editorList) {
			if (editor.getDataTypeManager() == dtm) {
				DataTypePath dtPath = editor.getDtPath();
				if (dtPath.getDataTypeName().equals(dtName)) {
					return true;
				}
			}
		}
		return false;
	}

	public void domainObjectRestored(DataTypeManagerDomainObject domainObject) {
		// Create a copy of the list since restore may remove an editor from the original list.
		ArrayList<EditorProvider> list = new ArrayList<>(editorList);
		// notify the editors
		for (EditorProvider editor : list) {
			DataTypeManager dataTypeManager = editor.getDataTypeManager();
			DataTypeManager programDataTypeManager = domainObject.getDataTypeManager();
			if (dataTypeManager == programDataTypeManager) {
				DataTypePath dtPath = editor.getDtPath();
				CategoryPath categoryPath = dtPath.getCategoryPath();
				String name = dtPath.getDataTypeName();
				DataType dataType = programDataTypeManager.getDataType(categoryPath, name);
				if (dataType == null || dataType.isDeleted()) {
					dismissEditor(editor);
					continue;
				}
				editor.domainObjectRestored(domainObject);
			}
		}
	}

	/**
	 * If the specified data type is being edited for the indicated category, this gets that editor.
	 * @param dataType the data type
	 * @return the editor or null.
	 */
	public EditorProvider getEditor(DataType dataType) {
		DataTypeManager catDtm = dataType.getDataTypeManager();
		DataTypePath dataTypePath = dataType.getDataTypePath();
		for (EditorProvider editor : editorList) {
			if (editor.getDataTypeManager() == catDtm && editor.isEditing(dataTypePath)) {
				return editor;
			}
		}
		return null;
	}

	/**
	 * Create the objects we need for this plugin; register the service
	 * provided, create the actions, etc.
	 */
	private void initialize() {
		editorList = new ArrayList<>();
		editorOptionMgr = new EditorOptionManager(plugin);

		installEditorActions();
	}

	/**
	 * EditorListener method that gets called whenever an editor is closed.
	 * @param editor the data type editor that closed
	 */
	@Override
	public void closed(EditorProvider editor) {
		editorList.remove(editor);
	}

	/**
	 * Determines whether there are any editors for data types that will be written to the
	 * indicated data type manager and that have unsaved changes.
	 * @param dtMgr the data type manager
	 * @return true if there are unsaved changes.
	 */
	boolean hasEditorChanges(DataTypeManager dtMgr) {
		for (EditorProvider editor : editorList) {
			DataTypeManager editorDtm = editor.getDataTypeManager();
			if (dtMgr == null || dtMgr == editorDtm) {
				if (editor.needsSave()) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Closes all open editors regardless of whether there are unsaved changes.
	 */
	void close() {
		dismissEditors(null);
	}

	/**
	 * Determines whether the indicated domain object can be closed. The user will be prompted
	 * to save any editor changes. If the user cancels when prompted to save then the domain
	 * object should not close.
	 * @param dObj the domain object
	 * @return true if it can close.
	 */
	protected boolean canCloseDomainObject(DomainObject dObj) {
		if (dObj instanceof Program) {
			Program p = (Program) dObj;
			return checkEditors(p.getListing().getDataTypeManager(), true);
		}
		return true;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.core.compositeeditor.StructureEditorOptionManager#showStructureCompOffsetInHex()
	 */
	@Override
	public boolean showStructureNumbersInHex() {
		return editorOptionMgr.showStructureNumbersInHex();
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.core.compositeeditor.UnionEditorOptionManager#showUnionCompLengthInHex()
	 */
	@Override
	public boolean showUnionNumbersInHex() {
		return editorOptionMgr.showUnionNumbersInHex();
	}

	public void createNewStructure(Category category, boolean isPacked) {
		String newName = getUniqueName(category, "struct");
		DataTypeManager dataTypeManager = category.getDataTypeManager();
		SourceArchive sourceArchive = dataTypeManager.getLocalSourceArchive();
		StructureDataType structureDataType =
			new StructureDataType(category.getCategoryPath(), newName, 0, dataTypeManager);
		structureDataType.setSourceArchive(sourceArchive);
		structureDataType.setPackingEnabled(isPacked);
		edit(structureDataType);
	}

	public void createNewUnion(Category category, boolean isPacked) {
		String newName = getUniqueName(category, "union");
		DataTypeManager dataTypeManager = category.getDataTypeManager();
		SourceArchive sourceArchive = dataTypeManager.getLocalSourceArchive();
		UnionDataType unionDataType =
			new UnionDataType(category.getCategoryPath(), newName, dataTypeManager);
		unionDataType.setSourceArchive(sourceArchive);
		unionDataType.setPackingEnabled(isPacked);
		edit(unionDataType);
	}

	public void createNewEnum(Category category) {
		String newName = getUniqueName(category, "enum");
		DataTypeManager dataTypeManager = category.getDataTypeManager();
		SourceArchive sourceArchive = dataTypeManager.getLocalSourceArchive();
		DataType dataType =
			new EnumDataType(category.getCategoryPath(), newName, 1, dataTypeManager);
		dataType.setSourceArchive(sourceArchive);
		edit(dataType);
	}

	public void createNewFunctionDefinition(Category cat) {
		editFunctionSignature(cat, null);
	}

	public void editFunctionSignature(final FunctionDefinition functionDefinition) {
		DataTypeManager dataTypeManager = functionDefinition.getDataTypeManager();
		if (dataTypeManager == null) {
			throw new IllegalArgumentException("DataType " + functionDefinition.getPathName() +
				" has no DataTypeManager!  Make sure the " +
				"given DataType has been resolved by a DataTypeManager");
		}
		CategoryPath categoryPath = functionDefinition.getCategoryPath();
		Category category = dataTypeManager.getCategory(categoryPath);
		if (categoryPath == null) {
			throw new IllegalArgumentException(
				"DataType " + functionDefinition.getName() + " has no category path!");
		}
		editFunctionSignature(category, functionDefinition);
	}

	private void editFunctionSignature(Category category, FunctionDefinition functionDefinition) {
		PluginTool tool = plugin.getTool();
		DTMEditFunctionSignatureDialog editSigDialog = new DTMEditFunctionSignatureDialog(
			plugin.getTool(), "Edit Function Signature", category, functionDefinition);
		editSigDialog.setHelpLocation(
			new HelpLocation("DataTypeManagerPlugin", "Function_Definition"));
		tool.showDialog(editSigDialog);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	/**
	 * <code>DTMEditFunctionSignatureDialog</code> provides the ability to edit the
	 * function signature associated with a specific {@link FunctionDefinition}.  
	 * Use of this editor requires the presence of the tool-based datatype manager service.
	 */
	private class DTMEditFunctionSignatureDialog extends AbstractEditFunctionSignatureDialog {
		private final FunctionDefinition functionDefinition;
		private final FunctionSignature oldSignature;
		private final Category category;

		DTMEditFunctionSignatureDialog(PluginTool pluginTool, String title, Category category,
				FunctionDefinition functionDefinition) {
			super(pluginTool, title, false, false, false);
			this.functionDefinition = functionDefinition;
			this.category = category;
			this.oldSignature = buildSignature();
		}

		private FunctionSignature buildSignature() {
			if (functionDefinition != null) {
				if (category.getDataTypeManager() != functionDefinition.getDataTypeManager()) {
					throw new IllegalArgumentException(
						"functionDefinition and category must have same Datatypemanager");
				}
				return functionDefinition;
			}
			return new FunctionDefinitionDataType("newFunction");
		}

		@Override
		protected String[] getSupportedCallFixupNames() {
			return null; // Call fixup not supported on FunctionDefinition
		}

		@Override
		protected String getCallFixupName() {
			return null; // Call fixup not supported on FunctionDefinition
		}

		@Override
		protected FunctionSignature getFunctionSignature() {
			return oldSignature;
		}

		@Override
		protected String getPrototypeString() {
			return getFunctionSignature().getPrototypeString();
		}

		@Override
		protected String getCallingConventionName() {
			return getFunctionSignature().getGenericCallingConvention().toString();
		}

		@Override
		protected List<String> getCallingConventionNames() {
			GenericCallingConvention[] values = GenericCallingConvention.values();
			List<String> choices = new ArrayList<>();
			for (GenericCallingConvention value : values) {
				choices.add(value.toString());
			}
			return choices;
		}

		@Override
		protected DataTypeManager getDataTypeManager() {
			return category.getDataTypeManager();
		}

		@Override
		protected boolean applyChanges() {
			// can't use a command here as we have to create a transaction on the datatypeManager
			// (it might be an archive and the transaction on the program wouldn't work)
			FunctionDefinitionDataType newDefinition = null;
			try {
				newDefinition = parseSignature();
			}
			catch (CancelledException e1) {
				// ignore
			}

			if (newDefinition == null) {
				return false;
			}

			GenericCallingConvention callingConvention =
				GenericCallingConvention.getGenericCallingConvention(getCallingConvention());
			newDefinition.setGenericCallingConvention(callingConvention);

			DataTypeManager manager = getDataTypeManager();
			SourceArchive sourceArchive = manager.getLocalSourceArchive();
			if (functionDefinition == null) {
				newDefinition.setSourceArchive(sourceArchive);
				newDefinition.setCategoryPath(category.getCategoryPath());
				int id = manager.startTransaction("Create Function Definition");
				manager.addDataType(newDefinition, DataTypeConflictHandler.REPLACE_HANDLER);
				manager.endTransaction(id, true);
			}
			else {
				int id = manager.startTransaction("Edit Function Definition");
				try {
					if (!functionDefinition.getName().equals(newDefinition.getName())) {
						functionDefinition.setName(newDefinition.getName());
					}
					functionDefinition.setArguments(newDefinition.getArguments());
					functionDefinition.setGenericCallingConvention(
						newDefinition.getGenericCallingConvention());
					functionDefinition.setReturnType(newDefinition.getReturnType());
					functionDefinition.setVarArgs(newDefinition.hasVarArgs());
				}
				catch (InvalidNameException | DuplicateNameException e) {
					// not sure why we are squashing this? ...assuming this can't happen
					Msg.error(this, "Unexpected Exception", e);
				}
				manager.endTransaction(id, true);
			}

			return true;
		}
	}

	// small class to register actions by name before the various editors have been shown
	private class DtSharedActionPlaceholder implements SharedDockingActionPlaceholder {

		private String name;

		DtSharedActionPlaceholder(String name) {
			this.name = CompositeEditorTableAction.EDIT_ACTION_PREFIX + name;
		}

		@Override
		public String getOwner() {
			// all of our shared actions belong to the plugin
			return plugin.getName();
		}

		@Override
		public String getName() {
			return name;
		}
	}
}
