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

import java.awt.event.ActionEvent;
import java.util.Objects;

import javax.swing.AbstractAction;

import docking.action.DockingActionIf;
import gui.event.MouseBinding;

/**
 * A class for using actions associated with mouse bindings. This class is meant to only by used by
 * internal Ghidra mouse event processing.
 */
public class DockingMouseBindingAction extends AbstractAction {

	private DockingActionIf dockingAction;
	private MouseBinding mouseBinding;

	public DockingMouseBindingAction(DockingActionIf action, MouseBinding mouseBinding) {
		this.dockingAction = Objects.requireNonNull(action);
		this.mouseBinding = Objects.requireNonNull(mouseBinding);
	}

	public String getFullActionName() {
		return dockingAction.getFullName();
	}

	@Override
	public boolean isEnabled() {
		return true; // always enable; this is a internal action that cannot be disabled
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		DockingActionPerformer.perform(dockingAction, e);
	}

	@Override
	public String toString() {
		return getFullActionName() + " (" + mouseBinding + ")";
	}
}
