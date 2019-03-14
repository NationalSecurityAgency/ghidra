/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;

import java.awt.event.ActionListener;

import javax.swing.*;

import docking.action.*;

/**
 * CompositeEditorAction is an abstract class that should be extended for any
 * action that is to be associated with a composite editor.
 */
abstract public class CompositeEditorAction extends DockingAction implements EditorAction {

	protected CompositeEditorProvider provider;
	protected CompositeEditorModel model;
	protected String tooltip;
	protected ImageIcon icon;
	protected ActionListener listener;
	protected String displayString;
	protected String actionCommand;
	protected JButton button; // corresponding JButton for this action
	protected KeyStroke keystroke;
	protected Plugin plugin;
	protected PluginTool tool;

	public static final String EDIT_ACTION_PREFIX = "Editor: ";

	/**
	 * Defines an <code>Action</code> object with the specified
	 * description string and a the specified icon.
	 */
	public CompositeEditorAction(CompositeEditorProvider provider, String name, String group,
			String[] popupPath, String[] menuPath, ImageIcon icon) {
		super(name, provider.plugin.getName());
		this.provider = provider;
		model = provider.getModel();
		if (menuPath != null) {
			setMenuBarData(new MenuData(menuPath, icon, group));
		}
		if (popupPath != null) {
			setPopupMenuData(new MenuData(popupPath, icon, group));
		}
		if (icon != null) {
			setToolBarData(new ToolBarData(icon, group));
		}
		this.plugin = provider.plugin;
		this.tool = plugin.getTool();
		model.addCompositeEditorModelListener(this);
		String helpAnchor = provider.getHelpName() + "_" + getHelpName();
		setHelpLocation(new HelpLocation(provider.getHelpTopic(), helpAnchor));
	}

	/* (non-Javadoc)
	 * @see ghidra.framework.plugintool.PluginAction#dispose()
	 */
	@Override
	public void dispose() {
		model.removeCompositeEditorModelListener(this);
		super.dispose();
		provider = null;
		model = null;
		plugin = null;
		tool = null;
	}

	protected void requestTableFocus() {
		JTable table = ((CompositeEditorPanel) provider.getComponent()).getTable();
		if (table.isEditing()) {
			table.getEditorComponent().requestFocus();
		}
		else {
			table.requestFocus();
		}
	}

	abstract public void adjustEnablement();

	public String getHelpName() {
		String actionName = getName();
		if (actionName.startsWith(CompositeEditorAction.EDIT_ACTION_PREFIX)) {
			actionName = actionName.substring(CompositeEditorAction.EDIT_ACTION_PREFIX.length());
		}
		return actionName;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.stackeditor.EditorModelListener#selectionChanged()
	 */
	public void selectionChanged() {
		adjustEnablement();
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.stackeditor.EditorModelListener#editStateChanged(int)
	 */
	public void editStateChanged(int i) {
		adjustEnablement();
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.CompositeEditorModelListener#compositeEditStateChanged(int)
	 */
	public void compositeEditStateChanged(int type) {
		adjustEnablement();
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.CompositeEditorModelListener#endFieldEditing()
	 */
	public void endFieldEditing() {
		adjustEnablement();
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.CompositeEditorModelListener#componentDataChanged()
	 */
	public void componentDataChanged() {
		adjustEnablement();
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.CompositeEditorModelListener#compositeInfoChanged()
	 */
	public void compositeInfoChanged() {
		adjustEnablement();
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.CompositeEditorModelListener#statusChanged(java.lang.String, boolean)
	 */
	public void statusChanged(String message, boolean beep) {
	}

	public void showUndefinedStateChanged(boolean showUndefinedBytes) {
		adjustEnablement();
	}

}
