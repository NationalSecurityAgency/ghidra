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
package ghidra.app.plugin.core.decompile.actions;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.util.HelpTopics;
import ghidra.util.HelpLocation;

/**
 * Action for adding all fields to the current format.
 */
public class SelectAllAction extends DockingAction {
	DecompilerPanel panel;

	public SelectAllAction(String owner, DecompilerPanel panel) {
		super("Select All", owner);
		this.panel = panel;
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_A, InputEvent.CTRL_DOWN_MASK));

		setHelpLocation(new HelpLocation(HelpTopics.SELECTION, getName()));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		panel.selectAll();
	}

}
