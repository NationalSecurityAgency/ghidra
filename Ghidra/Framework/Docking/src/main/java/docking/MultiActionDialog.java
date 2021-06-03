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

import java.awt.*;
import java.awt.event.*;
import java.util.List;

import javax.swing.*;

import docking.action.DockingActionIf;
import docking.event.mouse.GMouseListenerAdapter;
import docking.widgets.label.GIconLabel;
import docking.widgets.label.GLabel;

/**
 * Dialog to show multiple actions that are mapped to the same keystroke;
 * allows the user to select which action to do.
 */
public class MultiActionDialog extends DialogComponentProvider {

	private String keystrokeName;
	private List<ExecutableAction> list;
	private JList<String> actionList;
	private DefaultListModel<String> listModel;

	/**
	 * Constructor
	 * @param keystrokeName keystroke name
	 * @param list list of actions
	 */
	public MultiActionDialog(String keystrokeName, List<ExecutableAction> list) {
		super("Select Action", true);
		this.keystrokeName = keystrokeName;
		init();
		setActionList(list);
	}

	/**
	 * The callback method for when the "OK" button is pressed.
	 */
	@Override
	protected void okCallback() {
		maybeDoAction();
	}

	private void maybeDoAction() {
		int index = actionList.getSelectedIndex();
		if (index < 0) {
			return;
		}

		close();

		ExecutableAction actionProxy = list.get(index);
		actionProxy.execute();
	}

	/**
	 * Set the list of actions that are enabled
	 * @param list list of actions selected
	 */
	public void setActionList(List<ExecutableAction> list) {
		okButton.setEnabled(false);
		this.list = list;
		listModel.clear();
		for (int i = 0; i < list.size(); i++) {
			ExecutableAction actionProxy = list.get(i);
			DockingActionIf action = actionProxy.getAction();
			listModel.addElement(action.getName() + " (" + action.getOwnerDescription() + ")");
		}
		actionList.setSelectedIndex(0);
	}

	private void init() {
		this.addWorkPanel(buildMainPanel());
		addOKButton();
		addCancelButton();
		addListeners();
	}

	private JPanel buildMainPanel() {
		JPanel mainPanel = new JPanel(new BorderLayout());

		JPanel innerPanel = new JPanel(new BorderLayout());

		JPanel labelPanel = new JPanel(new GridLayout(0, 1));
		labelPanel.add(new GLabel("Multiple actions have been mapped to " + keystrokeName));
		labelPanel.add(new GLabel("Actions that can be enabled at the same"));
		labelPanel.add(new GLabel("time should be mapped to different keys"));

		innerPanel.setBorder(BorderFactory.createTitledBorder("Actions"));

		JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));

		Icon icon = UIManager.getIcon("OptionPane.warningIcon");
		panel.add(new GIconLabel(icon));
		panel.add(labelPanel);

		listModel = new DefaultListModel<>();
		actionList = new JList<>(listModel);

		actionList.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent evt) {
				if (evt.getKeyCode() == KeyEvent.VK_ENTER) {
					evt.consume();
					okCallback();

				}
				else if (evt.getKeyCode() == KeyEvent.VK_ESCAPE) {
					evt.consume();
					close();
				}
			}
		});

		actionList.addMouseListener(new GMouseListenerAdapter() {
			@Override
			public void doubleClickTriggered(MouseEvent e) {
				maybeDoAction();
			}
		});

		actionList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		actionList.setVisibleRowCount(5);
		JScrollPane listScrollPane = new JScrollPane(actionList);

		innerPanel.add(listScrollPane, BorderLayout.CENTER);

		mainPanel.add(panel, BorderLayout.NORTH);
		mainPanel.add(innerPanel, BorderLayout.CENTER);
		return mainPanel;
	}

	private void addListeners() {
		actionList.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {

				if (e.getModifiersEx() != InputEvent.BUTTON1_DOWN_MASK) {
					return;
				}
				int clickCount = e.getClickCount();
				if (clickCount == 2) {
					okCallback();
				}
			}
		});
		actionList.addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}
			okButton.setEnabled(!actionList.isSelectionEmpty());
		});
	}

}
