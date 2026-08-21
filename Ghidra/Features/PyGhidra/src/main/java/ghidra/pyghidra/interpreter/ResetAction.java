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
package ghidra.pyghidra.interpreter;

import java.awt.event.KeyEvent;
import javax.swing.ImageIcon;

import ghidra.pyghidra.PyGhidraPlugin;
import ghidra.util.HelpLocation;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.ToolBarData;
import resources.ResourceManager;

import static docking.DockingUtils.CONTROL_KEY_MODIFIER_MASK;

final class ResetAction extends DockingAction {

	private final PyGhidraConsole console;

	ResetAction(PyGhidraConsole console) {
		super("Reset", PyGhidraPlugin.class.getSimpleName());
		this.console = console;
		setDescription("Reset the interpreter");
		ImageIcon image = ResourceManager.loadImage("images/reload3.png");
		setToolBarData(new ToolBarData(image));
		setEnabled(true);
		KeyBindingData key = new KeyBindingData(KeyEvent.VK_D, CONTROL_KEY_MODIFIER_MASK);
		setKeyBindingData(key);
		setHelpLocation(new HelpLocation(PyGhidraPlugin.TITLE, "Reset_Interpreter"));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		console.restart();
	}
}
