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

import ghidra.util.StringUtilities;

import java.awt.event.*;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;

import javax.swing.*;

import docking.*;
import docking.action.*;

/**
 * Class to manager toolbar buttons.
 */
public class ToolBarItemManager implements PropertyChangeListener, ActionListener, MouseListener {

	private static final String START_KEYBINDING_TEXT = "<BR><HR><CENTER>(";
	private static final String END_KEYBINDNIG_TEXT = ")</CENTER>";

	private DockingActionIf toolBarAction;
	private JButton toolBarButton;
	private final DockingWindowManager windowManager;

	/**
	 * Constructs a new ToolBarItemManager
	 * @param action the action to be managed on the toolbar.
	 * @param iconSize the iconSize to scale to.
	 * @param buttonListener listener for button state changes.
	 */
	public ToolBarItemManager(DockingActionIf action, DockingWindowManager windowManager) {
		this.toolBarAction = action;
		this.windowManager = windowManager;
		action.addPropertyChangeListener(this);
	}

	/**
	 * Returns the group for this item.
	 */
	String getGroup() {
		return toolBarAction.getToolBarData().getToolBarGroup();
	}

	/**
	 * Returns a button for this items action.
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
		setToolTipText(button, action, getToolTipText(action));
		return button;
	}

	private void setToolTipText(JButton button, DockingActionIf action, String toolTipText) {
		String keyBindingText = getKeyBindingAcceleratorText(action.getKeyBinding());
		if (keyBindingText != null) {
			button.setToolTipText(combingToolTipTextWithKeyBinding(toolTipText, keyBindingText));
		}
		else {
			button.setToolTipText(toolTipText);
		}
		javax.swing.ToolTipManager instance = javax.swing.ToolTipManager.sharedInstance();
//        instance.unregisterComponent( button );        
	}

	private String combingToolTipTextWithKeyBinding(String toolTipText, String keyBindingText) {
		StringBuilder buffy = new StringBuilder(toolTipText);
		if (StringUtilities.startsWithIgnoreCase(toolTipText, "<HTML>")) {
			String endHTMLTag = "</HTML>";
			int closeTagIndex = StringUtilities.indexOfIgnoreCase(toolTipText, endHTMLTag);
			if (closeTagIndex < 0) {
				// no closing tag, which is acceptable
				buffy.append(START_KEYBINDING_TEXT).append(keyBindingText).append(
					END_KEYBINDNIG_TEXT);
			}
			else {
				// remove the closing tag, put on our text, and then put the tag back on
				buffy.delete(closeTagIndex, closeTagIndex + endHTMLTag.length() + 1);
				buffy.append(START_KEYBINDING_TEXT).append(keyBindingText).append(
					END_KEYBINDNIG_TEXT).append(endHTMLTag);
			}
			return buffy.toString();
		}

		// plain text (not HTML)
		return toolTipText + " (" + keyBindingText + ")";
	}

	private String getToolTipText(DockingActionIf action) {
		String description = action.getDescription();
		if (description != null && description.trim().length() > 0) {
			return description;
		}
		return action.getName();
	}

	private String getKeyBindingAcceleratorText(KeyStroke keyStroke) {
		if (keyStroke == null) {
			return null;
		}

		// This code is based on that of BasicMenuItemUI
		StringBuilder builder = new StringBuilder();
		int modifiers = keyStroke.getModifiers();
		if (modifiers > 0) {
			builder.append(KeyEvent.getKeyModifiersText(modifiers));
			builder.append('+');
		}
		int keyCode = keyStroke.getKeyCode();
		if (keyCode != 0) {
			builder.append(KeyEvent.getKeyText(keyCode));
		}
		else {
			builder.append(keyStroke.getKeyChar());
		}
		return builder.toString();
	}

	/**
	 * Returns the action being managed.
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
			setToolTipText(toolBarButton, toolBarAction, (String) e.getNewValue());
		}
		else if (name.equals(DockingActionIf.TOOLBAR_DATA_PROPERTY)) {
			ToolBarData toolBarData = (ToolBarData) e.getNewValue();
			toolBarButton.setIcon(toolBarData == null ? null : toolBarData.getIcon());
		}
		else if (name.equals(ToggleDockingActionIf.SELECTED_STATE_PROPERTY)) {
			toolBarButton.setSelected((Boolean) e.getNewValue());
		}
		else if (name.equals(DockingActionIf.KEYBINDING_DATA_PROPERTY)) {
			setToolTipText(toolBarButton, toolBarAction, getToolTipText(toolBarAction));
		}
	}

	@Override
	public void actionPerformed(ActionEvent event) {
		DockingWindowManager.clearMouseOverHelp();
		ActionContext localContext = getActionContext();
		ActionContext globalContext = null;
		if (windowManager != null) {
			globalContext = windowManager.getGlobalContext();
		}

		ActionContext tempContext = null;
		if (toolBarAction.isValidContext(localContext)) {
			tempContext = localContext; // we prefer the local over the global context if valid
		}
		else if (toolBarAction.isValidGlobalContext(globalContext)) {
			tempContext = globalContext;
		}
		else {
			return;  // context is not valid, nothing to do
		}
		tempContext.setSource(event.getSource());
		final ActionContext finalContext = tempContext;

		// this gives the UI some time to repaint before executing the action
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				if (toolBarAction.isEnabledForContext(finalContext)) {
					if (toolBarAction instanceof ToggleDockingActionIf) {
						ToggleDockingActionIf toggleAction = (ToggleDockingActionIf) toolBarAction;
						toggleAction.setSelected(!toggleAction.isSelected());
					}
					toolBarAction.actionPerformed(finalContext);
				}
			}
		});
	}

	@Override
	public String toString() {
		return toolBarAction.getName();
	}

	private ActionContext getActionContext() {
		ComponentProvider provider = getComponentProvider();
		ActionContext context = provider == null ? null : provider.getActionContext(null);
		final ActionContext actionContext = context == null ? new ActionContext() : context;
		return actionContext;
	}

	private ComponentProvider getComponentProvider() {
		DockingWindowManager manager = windowManager;
		if (manager == null) {
			manager = DockingWindowManager.getActiveInstance();
		}
		return manager.getActiveComponentProvider();
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
