/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package docking.menu;

import java.awt.event.*;

import docking.DockingWindowManager;
import docking.EmptyBorderToggleButton;
import docking.action.*;

/**
 * Toolbar buttons for Dialogs.  This class handles the peculiarities of DockableAction (see
 * the override notes below).
 */
public class DockingToolbarButton extends EmptyBorderToggleButton {
	private DockingActionIf dockableAction;
	private ActionContextProvider contextProvider;

	public DockingToolbarButton(DockingActionIf action, ActionContextProvider contextProvider) {
		super(action);
		this.contextProvider = contextProvider;
		setFocusable(false);
		addMouseListener(new MouseOverMouseListener());
		action.addPropertyChangeListener(propertyChangeListener);
	}

	@Override
	protected void initFromAction(DockingActionIf action) {
		dockableAction = action;
		super.initFromAction(action);
	}

	@Override
	protected void doActionPerformed(ActionEvent e) {
		if (dockableAction instanceof ToggleDockingActionIf) {
			ToggleDockingActionIf toggleAction = (ToggleDockingActionIf) dockableAction;
			toggleAction.setSelected(!toggleAction.isSelected());
		}
		dockableAction.actionPerformed(contextProvider.getActionContext(null));
	}

	@Override
	// overridden to account for the fact that "special" DockableActions can be either
	// toggle buttons or regular non-toggle buttons, which dictates whether this 
	// button is selected (non-toggle buttons are not selectable).
	protected boolean isButtonSelected() {
		if (dockableAction instanceof ToggleDockingAction) {
			return ((ToggleDockingAction) dockableAction).isSelected();
		}
		return false;
	}

	public DockingActionIf getDockingAction() {
		return dockableAction;
	}

	@Override
	// overridden to reflect the potentiality that our action is a toggle action
	public void setSelected(boolean b) {
		if (dockableAction instanceof ToggleDockingActionIf) {
			// only change the state if the action is a toggle action; doing otherwise would 
			// break the DockableAction
			((ToggleDockingActionIf) dockableAction).setSelected(b);
		}
		super.setSelected(b);
	}

	@Override
	// overridden to reflect the potentiality that our action is a toggle action
	public boolean isSelected() {
		if (dockableAction instanceof ToggleDockingActionIf) {
			return ((ToggleDockingActionIf) dockableAction).isSelected();
		}
		return super.isSelected();
	}

	@Override
	public void removeListeners() {
		dockableAction.removePropertyChangeListener(propertyChangeListener);
		super.removeListeners();
	}

	/** Activates/deactivates this button's action for things like help */
	private class MouseOverMouseListener extends MouseAdapter {

		@Override
		public void mouseEntered(MouseEvent me) {
			DockingWindowManager.setMouseOverAction(dockableAction);
		}

		@Override
		public void mouseExited(MouseEvent me) {
			DockingWindowManager.setMouseOverAction(null);
		}
	}
}
