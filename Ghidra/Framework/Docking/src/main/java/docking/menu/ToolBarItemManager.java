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
import java.beans.PropertyChangeListener;

import javax.swing.JButton;

import docking.ActionContext;
import docking.DockingWindowManager;
import docking.action.*;
import ghidra.util.Swing;

/**
 * Class to manager toolbar buttons.
 */
public class ToolBarItemManager implements PropertyChangeListener, ActionListener, MouseListener {

	private DockingActionIf toolBarAction;
	private JButton toolBarButton;
	private final DockingWindowManager windowManager;

	/**
	 * Constructs a new ToolBarItemManager
	 * @param action the action to be managed on the toolbar.
	 * @param windowManager the window manager.
	 */
	public ToolBarItemManager(DockingActionIf action, DockingWindowManager windowManager) {
		this.toolBarAction = action;
		this.windowManager = windowManager;
		action.addPropertyChangeListener(this);
	}

	String getGroup() {
		return toolBarAction.getToolBarData().getToolBarGroup();
	}

	/**
	 * Returns a button for this items action
	 * @return the button
	 */
	public JButton getButton() {
		if (toolBarButton == null) {
			toolBarButton = createButton(toolBarAction);
			toolBarButton.setEnabled(toolBarAction.isEnabled());
		}
		return toolBarButton;
	}

	public JButton createButton(final DockingActionIf action) {
		JButton button = action.createButton();
		button.addActionListener(this);
		button.addMouseListener(this);
		button.setName(action.getName());
		DockingToolBarUtils.setToolTipText(button, action);
		return button;
	}

	/**
	 * Returns the action being managed
	 * @return the action
	 */
	public DockingActionIf getAction() {
		return toolBarAction;
	}

	void dispose() {
		toolBarAction.removePropertyChangeListener(this);
		if (toolBarButton != null) {
			toolBarButton.removeActionListener(this);
			toolBarButton = null;
		}
	}

	@Override
	public void propertyChange(PropertyChangeEvent e) {
		if (toolBarButton == null) {
			return;
		}
		String name = e.getPropertyName();
		if (name.equals(DockingActionIf.ENABLEMENT_PROPERTY)) {
			toolBarButton.setEnabled(((Boolean) e.getNewValue()).booleanValue());
		}
		else if (name.equals(DockingActionIf.DESCRIPTION_PROPERTY)) {
			DockingToolBarUtils.setToolTipText(toolBarButton, toolBarAction);
		}
		else if (name.equals(DockingActionIf.TOOLBAR_DATA_PROPERTY)) {
			ToolBarData toolBarData = (ToolBarData) e.getNewValue();
			toolBarButton.setIcon(toolBarData == null ? null : toolBarData.getIcon());
		}
		else if (name.equals(ToggleDockingActionIf.SELECTED_STATE_PROPERTY)) {
			toolBarButton.setSelected((Boolean) e.getNewValue());
		}
		else if (name.equals(DockingActionIf.KEYBINDING_DATA_PROPERTY)) {
			DockingToolBarUtils.setToolTipText(toolBarButton, toolBarAction);
		}
	}

	@Override
	public void actionPerformed(ActionEvent event) {
		DockingWindowManager.clearMouseOverHelp();
		ActionContext context = getWindowManager().createActionContext(toolBarAction);

		context.setSourceObject(event.getSource());
		context.setEventClickModifiers(event.getModifiers());

		// this gives the UI some time to repaint before executing the action
		Swing.runLater(() -> {
			if (toolBarAction.isValidContext(context) &&
				toolBarAction.isEnabledForContext(context)) {
				if (toolBarAction instanceof ToggleDockingActionIf) {
					ToggleDockingActionIf toggleAction = (ToggleDockingActionIf) toolBarAction;
					toggleAction.setSelected(!toggleAction.isSelected());
				}
				toolBarAction.actionPerformed(context);
			}
		});
	}

	private DockingWindowManager getWindowManager() {
		if (windowManager != null) {
			return windowManager;
		}
		return DockingWindowManager.getActiveInstance();
	}

	@Override
	public String toString() {
		return toolBarAction.getName();
	}

	@Override
	public void mouseClicked(MouseEvent e) {
		// don't care
	}

	@Override
	public void mouseEntered(MouseEvent e) {
		DockingWindowManager.setMouseOverAction(toolBarAction);
	}

	@Override
	public void mouseExited(MouseEvent e) {
		DockingWindowManager.clearMouseOverHelp();
	}

	@Override
	public void mousePressed(MouseEvent e) {
		// don't care
	}

	@Override
	public void mouseReleased(MouseEvent e) {
		// don't care
	}
}
