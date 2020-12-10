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
package ghidra.app.plugin.core.debug.gui.objects.actions;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.List;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsProvider;
import ghidra.app.plugin.core.debug.gui.objects.ObjectContainer;
import ghidra.app.plugin.core.debug.gui.objects.components.ObjectTable;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;

public class DisplayFilteredTableAction extends DisplayFilteredAction {

	protected String lastCmd = "";

	public DisplayFilteredTableAction(PluginTool tool, String owner,
			DebuggerObjectsProvider provider) {
		super("DisplayFilteredTable", tool, owner, provider);
		String[] path = new String[] { "Display filtered...", "Table" };
		setPopupMenuData(new MenuData(path, ObjectTable.ICON_TABLE));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_T,
			InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK));
		setHelpLocation(new HelpLocation(owner, "display_filtered_table"));
		provider.addLocalAction(this);
	}

	@Override
	protected void doAction(ObjectContainer container, List<String> path) {
		ObjectContainer clone = ObjectContainer.clone(container);
		clone.setImmutable(true);
		getOffspring(clone, path);
	}

}
