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
package ghidra.app.plugin.core.decompiler.taint.actions;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.plugin.core.decompiler.taint.TaintPlugin;
import ghidra.app.plugin.core.decompiler.taint.TaintState;
import ghidra.app.util.HelpTopics;
import ghidra.util.HelpLocation;

/**
 * Action triggered from a specific token in the decompiler window to mark a variable as a source or
 * sink and generate the requisite query. This can be an input parameter, a stack variable, a
 * variable associated with a register, or a "dynamic" variable.
 */
public class TaintClearAction extends TaintAbstractDecompilerAction {

	private TaintPlugin plugin;
	private TaintState state;

	public TaintClearAction(TaintPlugin plugin, TaintState state) {
		super("Clear Markers");
		setHelpLocation(new HelpLocation(TaintPlugin.HELP_LOCATION, "TaintClear"));
		setPopupMenuData(new MenuData(new String[] { "Taint", "Clear" }, "Decompile"));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_S, InputEvent.CTRL_DOWN_MASK));
		this.plugin = plugin;
		this.state = state;
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		return true;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		state.clearMarkers();
		plugin.clearIcons();
		plugin.clearTaint();
		plugin.consoleMessage("taint cleared");
	}
}
