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
import docking.widgets.table.GTable;
import ghidra.app.plugin.core.datamgr.editor.DataTypeEditorManager;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;

/**
 * CompositeEditorAction is an abstract class that should be extended for any action that is to be 
 * associated with a composite editor.
 * <p>
 * Note: Any new actions must be registered in the editor manager via the actions's name.
 */
abstract public class CompositeEditorTableAction extends DockingAction implements EditorAction {

	private static final String PREFIX = DataTypeEditorManager.EDIT_ACTION_PREFIX;

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

	// note: Only call this constructor if you know you do not want to use the shared editor prefix;
	//       If you call this, then you must manage your own menu/popup/toolbar data installation
	protected CompositeEditorTableAction(CompositeEditorProvider provider, String name) {
		super(name, provider.plugin.getName());
		init(provider);
	}

	public CompositeEditorTableAction(CompositeEditorProvider provider, String name, String group,
			String[] popupPath, String[] menuPath, Icon icon) {
		super(PREFIX + name, provider.plugin.getName(),
			KeyBindingType.SHARED);
		init(provider);
		if (menuPath != null) {
			setMenuBarData(new MenuData(menuPath, icon, group));
		}
		if (popupPath != null) {
			setPopupMenuData(new MenuData(popupPath, icon, group));
		}
		if (icon != null) {
			setToolBarData(new ToolBarData(icon, group));
		}
	}

	private void init(CompositeEditorProvider editorProvider) {
		this.provider = editorProvider;
		this.model = provider.getModel();
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

	@Override
	abstract public void adjustEnablement();

	public String getHelpName() {
		String actionName = getName();
		if (actionName.startsWith(PREFIX)) {
			actionName = actionName.substring(PREFIX.length());
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
