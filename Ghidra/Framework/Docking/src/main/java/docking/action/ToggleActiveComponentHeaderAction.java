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
package docking.action;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.DockingWindowManager;

public class ToggleActiveComponentHeaderAction extends DockingAction {

	private DockingWindowManager windowManager;

	public ToggleActiveComponentHeaderAction(DockingWindowManager winMgr) {
		super("Toggle Component Title Bar/Header", DockingWindowManager.DOCKING_WINDOWS_OWNER);
		this.windowManager = winMgr;

		setDescription("Toggle visibility of the active component's title bar/header");
		createSystemKeyBinding(KeyStroke.getKeyStroke(
			KeyEvent.VK_H,
			InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK | InputEvent.ALT_DOWN_MASK));
		setEnabled(true);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		windowManager.toggleActiveComponentHeader();
	}
}
