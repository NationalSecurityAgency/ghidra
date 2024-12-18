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

import java.awt.event.MouseEvent;

import javax.swing.*;

import docking.*;
import docking.widgets.OptionDialog;
import docking.widgets.table.GTable;
import generic.theme.GIcon;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.datatype.EmptyCompositeException;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.AssertException;
import help.Help;
import help.HelpService;
import utilities.util.reflection.ReflectionUtilities;

/**
 * Editor provider for a Composite Data Type.
 */
public abstract class CompositeEditorProvider extends ComponentProviderAdapter
		implements EditorProvider, EditorActionListener {

	protected static final Icon EDITOR_ICON = new GIcon("icon.plugin.composite.editor.provider");

	protected Plugin plugin;
	protected Category category;
	protected CompositeEditorPanel editorPanel;
	protected CompositeEditorModel editorModel;
	protected WeakSet<EditorListener> listeners; // listeners for the editor closing.

	protected DataTypeManagerService dtmService;
	protected CompositeEditorActionManager actionMgr;

	/**
	 * Construct a new stack editor provider.
	 * @param plugin owner of this provider
	 */
	protected CompositeEditorProvider(Plugin plugin) {
		super(plugin.getTool(), "Composite Editor", plugin.getName());
		this.plugin = plugin;
		setIcon(EDITOR_ICON);
		setTransient();
		listeners = WeakDataStructureFactory.createSingleThreadAccessWeakSet();
		initializeServices();
	}

	protected String getProviderSubTitle(DataType dataType) {
		String dtmName;
		DataTypeManager dtm = editorModel.getOriginalDataTypeManager();
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

	protected void updateTitle() {
		setTabText(editorModel.originalComposite.getName());
		setTitle(getName() + " - " + getProviderSubTitle(editorModel.originalComposite));
	}

	protected CompositeEditorModel getModel() {
		return this.editorModel;
	}

	public JTable getTable() {
		return editorPanel.getTable();
	}

	public int getFirstEditableColumn(int row) {
		if (editorPanel == null) {
			return -1;
		}
		JTable table = editorPanel.getTable();
		int n = table.getColumnCount();
		for (int col = 0; col < n; col++) {
			if (table.isCellEditable(row, col)) {
				return col;
			}
		}
		return -1;
	}

	protected void initializeActions() {
		actionMgr = new CompositeEditorActionManager(this);
		actionMgr.setEditorActions(createActions());
		actionMgr.addEditorActionListener(this);
	}

	protected void addActionsToTool() {
		CompositeEditorTableAction[] allActions = actionMgr.getAllActions();
		for (CompositeEditorTableAction allAction : allActions) {
			tool.addLocalAction(this, allAction);
		}
	}

	protected CompositeEditorTableAction[] getActions() {
		return actionMgr.getAllActions();
	}

	@Override
	public void actionsAdded(CompositeEditorTableAction[] actions) {
		for (CompositeEditorTableAction action : actions) {
			tool.addLocalAction(this, action);
		}
	}

	@Override
	public void actionsRemoved(CompositeEditorTableAction[] actions) {
		for (CompositeEditorTableAction action : actions) {
			tool.removeLocalAction(this, action);
		}
	}

	/**
	 * Initialize services used
	 */
	protected void initializeServices() {

		dtmService = tool.getService(DataTypeManagerService.class);
		if (dtmService == null) {
			throw new AssertException("DataTypeManagerService was not found!");
		}
	}

	protected String getCompositeName() {
		return editorModel.getOriginalDataTypeName();
	}

	protected Plugin getPlugin() {
		return plugin;
	}

	@Override
	public void closeComponent() {
		closeComponent(false);
	}

	void closeComponent(boolean force) {
		if (editorModel != null && editorModel.editingField) {
			editorModel.endFieldEditing();
		}
		if (force || saveChanges(true) != 0) {
			super.closeComponent();
			dispose();
		}
	}

	@Override
	public JComponent getComponent() {
		return editorPanel;
	}

	public DataTypeManagerService getDtmService() {
		return dtmService;
	}

	@Override
	public DataTypeManager getDataTypeManager() {
		return editorModel.getOriginalDataTypeManager();
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {

		DataTypeComponent componentAt = null;
		int[] selectedComponentRows = editorModel.getSelectedComponentRows();
		if (selectedComponentRows.length == 1) {
			componentAt = editorModel.getComponent(selectedComponentRows[0]);
		}

		DataTypeManager originalDTM = editorModel.getOriginalDataTypeManager();
		if (originalDTM instanceof ProgramBasedDataTypeManager) {
			Program program = ((ProgramBasedDataTypeManager) originalDTM).getProgram();
			if (componentAt != null) {
				return new ComponentProgramActionContext(this, program, componentAt);
			}
			return new ProgramActionContext(this, program);
		}
		else if (componentAt != null && (originalDTM instanceof StandAloneDataTypeManager)) {
			return new ComponentStandAloneActionContext(this, componentAt);
		}
		return new DefaultActionContext(this, null);
	}

	@Override
	public HelpLocation getHelpLocation() {
		return new HelpLocation(getHelpTopic(), getHelpName());
	}

	public String getHelpName() {
		return this.getName();
	}

	public String getHelpTopic() {
		return this.getOwner();
	}

	@Override
	public void addEditorListener(EditorListener listener) {
		listeners.add(listener);
	}

	@Override
	public boolean checkForSave(boolean allowCancel) {
		return saveChanges(allowCancel) != 0;
	}

	@Override
	public void dispose() {
		tool.removeComponentProvider(this);
		for (EditorListener el : listeners) {
			el.closed(this);
		}
		actionMgr.dispose();
		editorPanel.dispose();
		editorModel.dispose();
	}

	@Override
	public ComponentProvider getComponentProvider() {
		return this;
	}

	@Override
	public DataTypePath getDtPath() {
		return editorModel.getOriginalDataTypePath();
	}

	@Override
	public boolean isEditing(DataTypePath path) {
		return getDtPath().equals(path);
	}

	@Override
	public boolean needsSave() {
		return editorModel.hasChanges();
	}

	@Override
	public void show() {
		tool.showComponentProvider(this, true);
	}

	protected void setStatusMessage(String msg) {
		tool.setStatusInfo(msg);
	}

	protected CompositeEditorTableAction[] createActions() {
		return new CompositeEditorTableAction[0];
	}

	protected boolean applyChanges() {
		try {
			return editorModel.apply();
		}
		catch (EmptyCompositeException e) {
			setStatusMessage(e.getMessage());
		}
		catch (InvalidDataTypeException e) {
			setStatusMessage(e.getMessage());
		}
		return false;
	}

	/**
	 * Prompts the user if the editor has unsaved changes. Saves the changes if
	 * the user indicates to do so.
	 * @param allowCancel true if allowed to cancel
	 * @return 0 if the user canceled; 1 if the user saved changes;
	 * 2 if the user did not to save changes; 3 if there was an error when
	 * the changes were applied.
	 */
	protected int saveChanges(boolean allowCancel) {
		// Check for changes and prompt user to check if saving them.
		if (editorModel.isValidName() && editorModel.hasChanges()) {
			String question = "The " + editorModel.getTypeName() + " Editor is closing.\n" +
				"Save the changes to " + getDtPath() + "?";
			String title = "Save " + editorModel.getTypeName() + " Editor Changes?";
			int response;
			if (allowCancel) {
				response = OptionDialog.showYesNoCancelDialog(editorPanel, title, question);
			}
			else {
				response = OptionDialog.showYesNoDialog(editorPanel, title, question);
			}
			if (response == 1) {
				// YES selected.
				if (!applyChanges()) {
					return 3;
				}
			}
			return response;
		}
		return 2;
	}

	@Override
	public String getWindowSubMenuName() {
		return getName();
	}

	@Override
	public boolean isTransient() {
		return true;
	}

	protected void registerHelp(Object object, String anchor) {
		String inception = recordHelpInception();
		HelpService help = Help.getHelpService();
		String fullAnchor = getHelpName() + "_" + anchor;
		help.registerHelp(object, new HelpLocation(getHelpTopic(), fullAnchor, inception));
	}

	private String recordHelpInception() {
		if (!SystemUtilities.isInDevelopmentMode()) {
			return "";
		}
		return getInceptionFromTheFirstClassThatIsNotUsOrABuilder();
	}

	protected String getInceptionFromTheFirstClassThatIsNotUsOrABuilder() {
		Throwable t = ReflectionUtilities.createThrowableWithStackOlderThan("registerHelp");
		return t.getStackTrace()[0].toString();
	}

	protected void requestTableFocus() {

		JTable table = editorPanel.getTable();
		if (!table.isEditing()) {
			table.requestFocus();
			return;
		}

		if (table instanceof GTable gTable) {
			gTable.requestTableEditorFocus();
		}
		else {
			table.getEditorComponent().requestFocus();
		}
	}

	protected void closeDependentEditors() {
		// do nothing by default
	}
}
