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

import java.awt.event.ActionListener;

import javax.swing.*;

import docking.action.*;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;

/**
 * CompositeEditorAction is an abstract class that should be extended for any
 * action that is to be associated with a composite editor.
 */
abstract public class CompositeEditorTableAction extends DockingAction implements EditorAction {

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

	public CompositeEditorTableAction(CompositeEditorProvider provider, String name, String group,
			String[] popupPath, String[] menuPath, ImageIcon icon) {
		super(name, provider.plugin.getName(), KeyBindingType.SHARED);
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
		if (provider == null) {
			return; // must have been disposed
		}
		JTable table = ((CompositeEditorPanel) provider.getComponent()).getTable();
		if (table.isEditing()) {
			table.getEditorComponent().requestFocus();
		}
		else {
			table.requestFocus();
		}
	}

	@Override
	abstract public void adjustEnablement();

	public String getHelpName() {
		String actionName = getName();
		if (actionName.startsWith(CompositeEditorTableAction.EDIT_ACTION_PREFIX)) {
			actionName =
				actionName.substring(CompositeEditorTableAction.EDIT_ACTION_PREFIX.length());
		}
		return actionName;
	}

	@Override
	public void selectionChanged() {
		adjustEnablement();
	}

	public void editStateChanged(int i) {
		adjustEnablement();
	}

	@Override
	public void compositeEditStateChanged(int type) {
		adjustEnablement();
	}

	@Override
	public void endFieldEditing() {
		adjustEnablement();
	}

	@Override
	public void componentDataChanged() {
		adjustEnablement();
	}

	@Override
	public void compositeInfoChanged() {
		adjustEnablement();
	}

	@Override
	public void statusChanged(String message, boolean beep) {
		// we are an action; don't care about status messages
	}

	@Override
	public void showUndefinedStateChanged(boolean showUndefinedBytes) {
		adjustEnablement();
	}

}
