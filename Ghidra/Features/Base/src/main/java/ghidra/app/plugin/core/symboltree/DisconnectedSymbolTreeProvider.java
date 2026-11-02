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
import ghidra.app.nav.DecoratorPanel;
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
			Program program, SymbolTreeFilterState filterState) {
		super(tool, plugin);
		this.filterState = filterState;
		setDefaultWindowPosition(WindowPosition.WINDOW);

		// Snapshots do not usually respond to incoming location events.  But, it seems to make 
		// sense that users would like to use the snapshot to navigate the tool.
		tool.removeLocalAction(this, navigateIncomingAction);
		navigateIncomingAction.setSelected(false);

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
	void programActivated(Program newProgram) {
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
	public void closeComponent() {
		plugin.closeDisconnectedProvider(this);
	}

	@Override
	void writeConfigState(SaveState saveState) {
		// we have no state we are interested in saving
	}

	@Override
	void readConfigState(SaveState saveState) {
		// we have no state we are interested in loading
	}
}
