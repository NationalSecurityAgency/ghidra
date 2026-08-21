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
 * CompositeEditorAction is an abstract class that should be extended for any action that is to be 
 * associated with a composite editor.
 * <p>
 * Note: Any new actions must be registered in the editor manager via the actions's name.
 */
abstract public class CompositeEditorTableAction extends DockingAction {

	static final String MAIN_ACTION_GROUP = "0_MAIN_EDITOR_ACTION";
	static final String UNDOREDO_ACTION_GROUP = "1_UNDOREDO_EDITOR_ACTION";
	static final String BASIC_ACTION_GROUP = "2_BASIC_EDITOR_ACTION";
	static final String DATA_ACTION_GROUP = "3_DATA_EDITOR_ACTION";
	static final String COMPONENT_ACTION_GROUP = "4_COMPONENT_EDITOR_ACTION";
	static final String BITFIELD_ACTION_GROUP = "5_COMPONENT_EDITOR_ACTION";

	protected CompositeEditorProvider<?, ?> provider;
	protected CompositeEditorModel<?> model;
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
	protected CompositeEditorTableAction(CompositeEditorProvider<?, ?> provider, String name) {
		super(name, provider.plugin.getName());
		init(provider);
	}

	public CompositeEditorTableAction(CompositeEditorProvider<?, ?> provider, String name,
			String group,
			String[] popupPath, String[] menuPath, Icon icon) {
		super(name, provider.plugin.getName(), KeyBindingType.SHARED);
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

	private void init(CompositeEditorProvider<?, ?> editorProvider) {
		this.provider = editorProvider;
		this.model = provider.getModel();
		this.plugin = provider.plugin;
		this.tool = plugin.getTool();
		String helpAnchor = provider.getHelpName() + "_" + getHelpName();
		setHelpLocation(new HelpLocation(provider.getHelpTopic(), helpAnchor));
	}

	@Override
	public void dispose() {
		super.dispose();
		provider = null;
		model = null;
		plugin = null;
		tool = null;
	}

	protected boolean hasIncompleteFieldEntry() {
		return provider.editorPanel.hasInvalidEntry() || provider.editorPanel.hasUncomittedEntry();
	}

	protected void requestTableFocus() {
		if (provider != null) {
			provider.requestTableFocus();
		}
	}

	public String getHelpName() {
		return getName();
	}

}
