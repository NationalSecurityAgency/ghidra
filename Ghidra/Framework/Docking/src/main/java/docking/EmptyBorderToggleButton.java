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
import java.awt.event.ActionListener;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;

import javax.swing.*;

import docking.action.DockingActionIf;
import docking.action.ToolBarData;
import docking.widgets.EmptyBorderButton;

public class EmptyBorderToggleButton extends EmptyBorderButton {

	private ActionListener toggleButtonActionListener = e -> doActionPerformed(e);

	protected PropertyChangeListener propertyChangeListener = evt -> doPropertyChange(evt);

	public EmptyBorderToggleButton() {
		super();
		init();
	}

	public EmptyBorderToggleButton(Icon icon) {
		super(icon);
		init();
	}

	public EmptyBorderToggleButton(DockingActionIf action) {
		super();

		// Note: do not pass the action up to super, since the JButton ancestor will perform
		// initialization from the action that we have not been designed to handle (we shouldn't 
		// have to change the way that Java uses actions, but that is for a later refactoring).
		initFromAction(action);
		updateBorder(); // synch up the action with the border
		init();
	}

	protected void initFromAction(DockingActionIf action) {
		if (action == null) {
			return;
		}
		ToolBarData toolBarData = action.getToolBarData();
		Icon icon = toolBarData == null ? null : toolBarData.getIcon();
		setIcon(icon);
		String tt = action.getDescription();
		if (tt == null || tt.length() == 0) {
			tt = action.getName();
		}
		setToolTipText(tt);
		setEnabled(action.isEnabled());
	}

	private void init() {
		addActionListener(toggleButtonActionListener);
		addPropertyChangeListener(propertyChangeListener);
	}

	@Override
	public void removeListeners() {
		super.removeListeners();
		removeActionListener(toggleButtonActionListener);
		removePropertyChangeListener(propertyChangeListener);
	}

	private void updateBorder() {
		if (isButtonSelected()) {
			setBorder(LOWERED_BUTTON_BORDER);
		}
		else {
			setBorder(NO_BUTTON_BORDER);
		}
	}

	protected boolean isButtonSelected() {
		return isSelected();
	}

	// This method only functions if this class was created with an action
	protected void doActionPerformed(ActionEvent e) {
		setSelected(!isSelected()); // toggle

		Action buttonAction = getAction();
		if (buttonAction == null) {
			return;
		}
		buttonAction.actionPerformed(e);
	}

	protected void doPropertyChange(PropertyChangeEvent e) {
		String name = e.getPropertyName();
		if (name.equals("enabled")) {
			setEnabled(((Boolean) e.getNewValue()).booleanValue());
		}
		else if (name.equals(Action.SHORT_DESCRIPTION)) {
			setToolTipText((String) e.getNewValue());
		}
		else if (name.equals(Action.SMALL_ICON)) {
			setIcon((Icon) e.getNewValue());
		}
		else if (name.equals("CheckBoxState")) {
			updateBorder();
		}
	}

	@Override
	// overridden to handle our selected state and the depressed border
	public void clearBorder() {
		if (isButtonSelected()) {
			setBorder(LOWERED_BUTTON_BORDER);
			return;
		}
		super.clearBorder();
	}

	@Override
	// overridden to handle our selected state and the depressed border
	public void raiseBorder() {
		if (isButtonSelected()) {
			// do nothing if we are selected
			return;
		}
		super.raiseBorder();
	}

	@Override
	public void setIcon(Icon newIcon) {
		super.setIcon(DockingUtils.scaleIconAsNeeded(newIcon));
	}

	protected void doSetIcon(Icon newIcon) {
		super.setIcon(newIcon);
	}

	@Override
	public void setSelected(boolean b) {

		boolean state = updateStateFromButtonGroup(b);

		super.setSelected(state);
		updateBorder();
	}

	private boolean updateStateFromButtonGroup(boolean b) {
		ButtonModel bm = getModel();
		if (!(bm instanceof DefaultButtonModel)) {
			return b;
		}

		DefaultButtonModel buttonModel = (DefaultButtonModel) bm;
		ButtonGroup group = buttonModel.getGroup();
		if (group == null) {
			return b;
		}

		group.setSelected(buttonModel, b);
		boolean isSelected = group.isSelected(buttonModel);
		return isSelected;
	}

	/**
	 * Changes the button's state to the opposite of its current state.  Calling this method 
	 * will also trigger a callback to the button's {@link Action#actionPerformed(ActionEvent)}
	 * method.
	 */
	public void toggle() {
		doClick();
	}

	@Override
	// overridden to handle our selected state
	protected void updateBorderBasedOnState() {
		if (isButtonSelected()) {
			return;
		}
		super.updateBorderBasedOnState();
	}
}
