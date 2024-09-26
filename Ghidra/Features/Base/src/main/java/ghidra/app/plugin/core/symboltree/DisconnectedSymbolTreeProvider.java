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
package ghidra.app.plugin.core.symboltree;

import javax.swing.JComponent;
import javax.swing.JPanel;

import docking.WindowPosition;
import docking.action.KeyBindingData;
import docking.action.builder.ActionBuilder;
import ghidra.app.nav.DecoratorPanel;
import ghidra.app.plugin.core.symboltree.nodes.*;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;

/**
 * A disconnected symbol tree is a snapshot of the primary symbol tree.
 */
public class DisconnectedSymbolTreeProvider extends SymbolTreeProvider {

	private static final String WINDOW_GROUP = "Disconnected Symbol Tree";

	public DisconnectedSymbolTreeProvider(PluginTool tool, SymbolTreePlugin plugin,
			Program program) {
		super(tool, plugin);

		setDefaultWindowPosition(WindowPosition.WINDOW);

		createActions();

		// Snapshots do not usually track events.  Turn this off now, but leave the action so 
		// clients can turn the action on as desired.
		goToToggleAction.setEnabled(false);

		setHelpLocation(new HelpLocation("SymbolTreePlugin", "Disconnected_Symbol_Tree"));

		this.program = program;
		program.addListener(domainObjectListener);

		rebuildTree();
	}

	@Override
	public String getWindowGroup() {
		return WINDOW_GROUP;
	}

	@Override
	public WindowPosition getDefaultWindowPosition() {
		return WindowPosition.WINDOW;
	}

	@Override
	public boolean isTransient() {
		return true;
	}

	@Override
	public boolean isSnapshot() {
		return true;
	}

	@Override
	protected void addToToolbar() {
		// do not add the disconnected provider to the toolbar
	}

	@Override
	protected void setKeyBinding(KeyBindingData kbData) {
		// no keybinding for the disconnected provider
	}

	@Override
	void setProgram(Program newProgram) {
		// nothing to do; we maintain our state as the user changes programs
	}

	@Override
	void programDeactivated(Program deactivatedProgram) {
		// nothing to do; we maintain our state as the user changes programs
	}

	@Override
	void programClosed(Program closedProgram) {
		tree.cancelWork();

		closedProgram.removeListener(domainObjectListener);

		program = null;
		rebuildTree();

		closeComponent();
	}

	@Override
	protected JPanel createMainPanel(JComponent contentComponent) {
		return new DecoratorPanel(contentComponent, false);
	}

	@Override
	protected SymbolTreeRootNode createRootNode() {
		return new ConfigurableSymbolTreeRootNode(program);
	}

	@Override
	public void closeComponent() {
		plugin.closeDisconnectedProvider(this);
	}

	@Override
	protected void transferSettings(DisconnectedSymbolTreeProvider newProvider) {

		// transfer disabled node settings
		ConfigurableSymbolTreeRootNode myModelRoot =
			(ConfigurableSymbolTreeRootNode) tree.getModelRoot();

		ConfigurableSymbolTreeRootNode newModelRoot =
			(ConfigurableSymbolTreeRootNode) newProvider.tree.getModelRoot();
		myModelRoot.transferSettings(newModelRoot);

		super.transferSettings(newProvider);
	}

	@Override
	void writeConfigState(SaveState saveState) {
		// we have no state we are interested in saving
	}

	@Override
	void readConfigState(SaveState saveState) {
		// we have no state we are interested in loading
	}

	private void createActions() {

		//@formatter:off
		new ActionBuilder("Enable Category", plugin.getName())
			.popupMenuPath("Enable Category")
			.withContext(SymbolTreeActionContext.class)
			.enabledWhen(c -> {				
				SymbolTreeNode node = c.getSelectedNode();
				return node instanceof SymbolCategoryNode;	
			})
			.onAction(c -> {
				SymbolCategoryNode node = (SymbolCategoryNode) c.getSelectedNode();
				node.setEnabled(true);
			})
			.buildAndInstallLocal(this);
		//@formatter:on

		//@formatter:off
		new ActionBuilder("Disable Category", plugin.getName())
			.popupMenuPath("Disable Category")
			.withContext(SymbolTreeActionContext.class)
			.enabledWhen(c -> {				
				SymbolTreeNode node = c.getSelectedNode();
				return node instanceof SymbolCategoryNode;	
			})
			.onAction(c -> {
				SymbolCategoryNode node = (SymbolCategoryNode) c.getSelectedNode();
				node.setEnabled(false);
			})
			.buildAndInstallLocal(this);
		//@formatter:on
	}
}
