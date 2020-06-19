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
package docking.menu;

import java.awt.event.*;
import java.beans.PropertyChangeEvent;

import docking.DockingWindowManager;
import docking.EmptyBorderToggleButton;
import docking.action.*;

/**
 * Toolbar buttons for Dialogs.   
 * 
 * <p>This class exists because dialog actions are not added to the regular tool's toolbars.  This
 * means that we have to create the dialog's toolbars outside of the tool.  Thus, this class
 * mimics how the tool's toolbar buttons are created.
 */
public class DialogToolbarButton extends EmptyBorderToggleButton {
	private DockingActionIf dockingAction;
	private ActionContextProvider contextProvider;

	public DialogToolbarButton(DockingActionIf action, ActionContextProvider contextProvider) {
		super(action);
		this.contextProvider = contextProvider;
		setFocusable(false);
		addMouseListener(new MouseOverMouseListener());
		action.addPropertyChangeListener(propertyChangeListener);

		// make sure this button gets our specialized tooltip 
		DockingToolBarUtils.setToolTipText(this, dockingAction);
	}

	@Override
	protected void initFromAction(DockingActionIf action) {
		dockingAction = action;
		super.initFromAction(action);
	}

	@Override
	protected void doActionPerformed(ActionEvent e) {
		if (dockingAction instanceof ToggleDockingActionIf) {
			ToggleDockingActionIf toggleAction = (ToggleDockingActionIf) dockingAction;
			toggleAction.setSelected(!toggleAction.isSelected());
		}
		dockingAction.actionPerformed(contextProvider.getActionContext(null));
	}

	@Override
	protected void doPropertyChange(PropertyChangeEvent e) {
		super.doPropertyChange(e);

		String name = e.getPropertyName();
		if (name.equals(DockingActionIf.ENABLEMENT_PROPERTY)) {
			setEnabled(((Boolean) e.getNewValue()).booleanValue());
		}
		else if (name.equals(DockingActionIf.DESCRIPTION_PROPERTY)) {
			DockingToolBarUtils.setToolTipText(this, dockingAction);
		}
		else if (name.equals(DockingActionIf.TOOLBAR_DATA_PROPERTY)) {
			ToolBarData toolBarData = (ToolBarData) e.getNewValue();
			setIcon(toolBarData == null ? null : toolBarData.getIcon());
		}
		else if (name.equals(ToggleDockingActionIf.SELECTED_STATE_PROPERTY)) {
			setSelected((Boolean) e.getNewValue());
		}
		else if (name.equals(DockingActionIf.KEYBINDING_DATA_PROPERTY)) {
			DockingToolBarUtils.setToolTipText(this, dockingAction);
		}
	}

	@Override
	// overridden to account for the fact that "special" DockableActions can be either
	// toggle buttons or regular non-toggle buttons, which dictates whether this 
	// button is selected (non-toggle buttons are not selectable).
	protected boolean isButtonSelected() {
		if (dockingAction instanceof ToggleDockingAction) {
			return ((ToggleDockingAction) dockingAction).isSelected();
		}
		return false;
	}

	public DockingActionIf getDockingAction() {
		return dockingAction;
	}

	@Override
	// overridden to reflect the potentiality that our action is a toggle action
	public void setSelected(boolean b) {
		if (dockingAction instanceof ToggleDockingActionIf) {
			// only change the state if the action is a toggle action; doing otherwise would 
			// break the DockableAction
			((ToggleDockingActionIf) dockingAction).setSelected(b);
		}
		super.setSelected(b);
	}

	@Override
	// overridden to reflect the potentiality that our action is a toggle action
	public boolean isSelected() {
		if (dockingAction instanceof ToggleDockingActionIf) {
			return ((ToggleDockingActionIf) dockingAction).isSelected();
		}
		return super.isSelected();
	}

	@Override
	public void removeListeners() {
		dockingAction.removePropertyChangeListener(propertyChangeListener);
		super.removeListeners();
	}

	/** Activates/deactivates this button's action for things like help */
	private class MouseOverMouseListener extends MouseAdapter {

		@Override
		public void mouseEntered(MouseEvent me) {
			DockingWindowManager.setMouseOverAction(dockingAction);
		}

		@Override
		public void mouseExited(MouseEvent me) {
			DockingWindowManager.setMouseOverAction(null);
		}
	}
}
