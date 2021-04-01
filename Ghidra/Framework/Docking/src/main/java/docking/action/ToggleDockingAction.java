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

import javax.swing.JButton;
import javax.swing.JMenuItem;

import docking.*;

public abstract class ToggleDockingAction extends DockingAction implements ToggleDockingActionIf {
	private boolean isSelected;

	public ToggleDockingAction(String name, String owner) {
		super(name, owner);
	}

	public ToggleDockingAction(String name, String owner, KeyBindingType keyBindingType) {
		super(name, owner, keyBindingType);
	}

	public ToggleDockingAction(String name, String owner, boolean supportsKeyBindings) {
		super(name, owner, supportsKeyBindings);
	}

	@Override
	public boolean isSelected() {
		return isSelected;
	}

	@Override
	public void setSelected(boolean newValue) {
		if (isSelected == newValue) {
			return;
		}
		isSelected = newValue;
		firePropertyChanged(SELECTED_STATE_PROPERTY, !isSelected, isSelected);
	}

	@Override
	protected JButton doCreateButton() {
		EmptyBorderToggleButton button = new EmptyBorderToggleButton();
		button.setSelected(isSelected);
		return button;
	}

	@Override
	protected JMenuItem doCreateMenuItem() {
		return new DockingCheckBoxMenuItem(isSelected);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		// defined by subclasses
	}

}
