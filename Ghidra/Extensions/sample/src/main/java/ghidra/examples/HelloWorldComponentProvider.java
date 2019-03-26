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
package ghidra.examples;

import java.awt.*;
import java.awt.event.*;

import javax.swing.*;

import docking.ActionContext;
import docking.WindowPosition;
import docking.action.*;
import docking.widgets.EmptyBorderButton;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resources.ResourceManager;

public class HelloWorldComponentProvider extends ComponentProviderAdapter {
	private final static String PREV_IMAGE = "images/information.png";
	private final static HelpLocation HELP = new HelpLocation("SampleHelpTopic",
		"SampleHelpTopic_Anchor_Name");
	private MyButton activeButtonObj;
	private JPanel mainPanel;
	private DockingAction action;

	public HelloWorldComponentProvider(PluginTool tool, String name) {
		super(tool, name, name);
		buildMainPanel();
		setIcon(ResourceManager.loadImage("images/erase16.png"));
		setHelpLocation(HELP);
		setDefaultWindowPosition(WindowPosition.WINDOW);
		setTitle("Hello World Component");
		setVisible(true);
		createActions();
	}

	private void createActions() {

		// set actions for Hello->World menu item
		action = new DockingAction("Hello World", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				// pop up a "Hello World" dialog
				announce("Hello World");
			}
		};

		action.setEnabled(true);

		// put in Menu called "Hello", with Menu item of "World".  Since this will be a local action
		// the menu item will appear on the local toolbar drop down.
		ImageIcon prevImage = ResourceManager.loadImage(PREV_IMAGE);
		action.setMenuBarData(new MenuData(new String[] { "Misc", "Hello World" }, prevImage));
		action.setKeyBindingData(new KeyBindingData(KeyStroke.getKeyStroke(KeyEvent.VK_W,
			InputEvent.CTRL_MASK)));

		// puts the action on the local toolbar.
		action.setToolBarData(new ToolBarData(prevImage));
		action.setDescription("Hello World");

		// set the help URL for the action
		action.setHelpLocation(HELP);
		addLocalAction(action);

		//Example popup action
		DockingAction popupAction = new DockingAction("Hello Popup", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				announce("Hello World");

				// To get the context object,				
				Object contextObject = context.getContextObject();

				// ...now we can cast activeObj to be a object of MyButton
				// if that is necessary, as the overridden isAddToPopup() method below 
				// will not add the popup action if the context object is not our button

				@SuppressWarnings("unused")
				MyButton myButton = (MyButton) contextObject;
				// use my button for something interesting...
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				// popup only if menu is over MyButton (to demo context--this is created below
				// in getActionContext(MouseEvent))
				if (context.getContextObject() instanceof MyButton) {
					return true;
				}
				return false;
			}
		};
		popupAction.setEnabled(true);
		popupAction.setPopupMenuData(new MenuData(new String[] { "Example of Popup" }));
		addLocalAction(popupAction);

	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	private void buildMainPanel() {
		mainPanel = new JPanel(new BorderLayout());
		mainPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 10));
		JPanel panel = new JPanel(new FlowLayout(FlowLayout.CENTER));
		panel.setBorder(BorderFactory.createTitledBorder("Example of a Component"));
		activeButtonObj = new MyButton("Hello World");
		Font f = activeButtonObj.getFont();
		activeButtonObj.setFont(new Font(f.getFontName(), Font.BOLD, 14));
		panel.add(activeButtonObj);
		mainPanel.add(panel, BorderLayout.CENTER);
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (event != null) {
			Object source = event.getSource();
			if (source == activeButtonObj) {
				return new ActionContext(this, activeButtonObj);
			}
		}
		return null;
	}

	/**
	 * popup the Hello Dialog
	 */
	protected void announce(String message) {
		Msg.showInfo(getClass(), mainPanel, "Hello World", message);
	}

	private class MyButton extends EmptyBorderButton {
		MyButton(String name) {
			super(name);
			setBorder(BorderFactory.createEmptyBorder(10, 5, 10, 5));

			addActionListener(new ActionListener() {

				@Override
				public void actionPerformed(ActionEvent e) {
					announce("Hello World");
				}
			});
		}
	}
}
