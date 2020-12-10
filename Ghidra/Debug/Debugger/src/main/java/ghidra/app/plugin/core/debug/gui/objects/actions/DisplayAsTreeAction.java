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

import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsProvider;
import ghidra.app.plugin.core.debug.gui.objects.ObjectContainer;
import ghidra.app.plugin.core.debug.gui.objects.components.ObjectTree;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;

public class DisplayAsTreeAction extends DisplayAsAction {

	public DisplayAsTreeAction(PluginTool tool, String owner, DebuggerObjectsProvider provider) {
		super("DisplayTree", tool, owner, provider);
		isTree = true;
		String[] path = new String[] { "Display as...", "Tree" };
		setPopupMenuData(new MenuData(path, ObjectTree.ICON_TREE));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_R, InputEvent.CTRL_DOWN_MASK));
		setHelpLocation(new HelpLocation(owner, "display_as_tree"));
		provider.addLocalAction(this);
	}

	@Override
	protected void doAction(ObjectContainer container) {
		ObjectContainer clone = new ObjectContainer(container.getTargetObject(), container.linkKey);
		finishGetOffspring(clone);
		//getOffspring(clone);
	}

}
