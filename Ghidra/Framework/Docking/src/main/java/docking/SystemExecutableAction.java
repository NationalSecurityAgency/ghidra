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
package docking;

import java.awt.Component;

import javax.help.UnsupportedOperationException;

import docking.action.DockingActionIf;
import docking.action.ToggleDockingActionIf;

public class SystemExecutableAction implements ExecutableAction {
	private DockingActionIf action;
	private ActionContext context;

	public SystemExecutableAction(DockingActionIf action, ActionContext context) {
		this.action = action;
		this.context = context;
	}

	@Override
	public boolean isValid() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}

	@Override
	public void reportNotEnabled(Component focusOwner) {
		// we are always enabled
		throw new UnsupportedOperationException();
	}

	@Override
	public KeyBindingPrecedence getKeyBindingPrecedence() {
		return action.getKeyBindingData().getKeyBindingPrecedence();
	}

	@Override
	public void execute() {
		// Toggle actions do not toggle its state directly therefor we have to do it for 
		// them before we execute the action.
		if (action instanceof ToggleDockingActionIf) {
			ToggleDockingActionIf toggleAction = (ToggleDockingActionIf) action;
			toggleAction.setSelected(!toggleAction.isSelected());
		}

		action.actionPerformed(context);
	}

	@Override
	public String toString() {
		return action.getFullName();
	}
}
