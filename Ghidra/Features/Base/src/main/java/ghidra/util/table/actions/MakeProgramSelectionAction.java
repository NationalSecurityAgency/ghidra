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
package ghidra.util.table.actions;

import java.awt.Component;

import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.action.*;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.table.GhidraTable;
import resources.Icons;

/**
 * An action to make a program selection based on the given table's selection.  For the context to
 * work, the provider using this action must create an {@link ActionContext} that returns a 
 * context object that is the table passed to this action's constructor; otherwise, this action 
 * will not be enabled correctly.
 */
public class MakeProgramSelectionAction extends DockingAction {

	// we will have one of these fields be non-null after construction
	private Plugin plugin;
	private GhidraTable table;

	/**
	 * Special constructor for clients that do not have a plugin.  Clients using this 
	 * constructor must override {@link #makeSelection(ActionContext)}.
	 * 
	 * @param owner the action's owner
	 * @param table the table needed for this action
	 */
	public MakeProgramSelectionAction(String owner, GhidraTable table) {
		super("Make Selection", owner, KeyBindingType.SHARED);
		this.table = table;
		init();
	}

	/**
	 * This normal constructor for this action.  The given plugin will be used along with the
	 * given table to fire program selection events as the action is executed.
	 * 
	 * @param plugin the plugin
	 * @param table the table
	 */
	public MakeProgramSelectionAction(Plugin plugin, GhidraTable table) {
		super("Make Selection", plugin.getName(), KeyBindingType.SHARED);
		this.plugin = plugin;
		this.table = table;

		init();
	}

	private void init() {
		setPopupMenuData(
			new MenuData(new String[] { "Make Selection" }, Icons.MAKE_SELECTION_ICON));
		setToolBarData(new ToolBarData(Icons.MAKE_SELECTION_ICON));
		setDescription("Make a program selection from the selected rows");

		// this help location provides generic help; clients can override to point to their help
		setHelpLocation(new HelpLocation("Search", "Make_Selection"));

		// null for now, but we may want a default binding in the future
		initKeyStroke(null);
	}

	private void initKeyStroke(KeyStroke keyStroke) {
		if (keyStroke == null) {
			return;
		}

		setKeyBindingData(new KeyBindingData(keyStroke));
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		return true;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {

		Component component = context.getSourceComponent();
		if (component != table) {
			return false;
		}

		Program program = table.getProgram();
		if (program == null) {
			return false;
		}

		if (program.isClosed()) {
			return false;
		}

		int n = table.getSelectedRowCount();
		return n > 0;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		makeSelection(context);
	}

	protected ProgramSelection makeSelection(ActionContext context) {
		ProgramSelection selection = table.getProgramSelection();

		if (plugin == null) {
			throw new IllegalStateException("The Make Program Selection action cannot be used " +
				"without a plugin unless the client overrides this method");
		}

		PluginEvent event =
			new ProgramSelectionPluginEvent(plugin.getName(), selection, table.getProgram());
		plugin.firePluginEvent(event);
		return selection;
	}
}
