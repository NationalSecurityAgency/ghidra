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
package ghidra.app.merge.tree;

import java.awt.*;

import javax.swing.*;

import docking.widgets.label.GDLabel;
import docking.widgets.label.GIconLabel;
import generic.theme.GIcon;
import generic.theme.GThemeDefaults.Colors;
import generic.theme.GThemeDefaults.Colors.Messages;
import ghidra.util.layout.PairLayout;
import resources.Icons;

/**
 * Panel to show whether tree name and tree structure changed.
 * 
 * 
 */
class TreeChangePanel extends JPanel {

	private JLabel treeNameLabel;
	private JLabel nameLabel;
	private JLabel structureLabel;
	private JPanel namePanel;
	private JPanel structurePanel;
	private JLabel nameIconLabel;
	private JLabel structureIconLabel;

	private final static Icon CHANGED_ICON = new GIcon("icon.plugin.merge.changed");
	private final static Icon NO_CHANGE_ICON = Icons.EMPTY_ICON;
	private final static Color CHANGED_COLOR = Colors.FOREGROUND;
	private final static Color NO_CHANGE_COLOR = Messages.HINT;

	TreeChangePanel(String title) {
		super(new BorderLayout());
		setBorder(BorderFactory.createTitledBorder(title));
		create();
	}

	void setStates(String treeName, boolean nameChanged, boolean structureChanged) {

		treeNameLabel.setText(treeName);
		nameLabel.setText(nameChanged ? "Name Changed" : "Name Not Changed");
		nameLabel.setForeground(nameChanged ? CHANGED_COLOR : NO_CHANGE_COLOR);
		namePanel.remove(nameIconLabel);
		nameIconLabel = new GIconLabel(nameChanged ? CHANGED_ICON : NO_CHANGE_ICON);
		namePanel.add(nameIconLabel, 0);

		structureLabel.setText(structureChanged ? "Structure Changed" : "Structure Not Changed");
		structureLabel.setForeground(structureChanged ? CHANGED_COLOR : NO_CHANGE_COLOR);
		structurePanel.remove(structureIconLabel);
		structureIconLabel = new GIconLabel(structureChanged ? CHANGED_ICON : NO_CHANGE_ICON);
		structurePanel.add(structureIconLabel, 0);
	}

	private void create() {
		JPanel panel = new JPanel(new BorderLayout(0, 5));
		panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

		treeNameLabel = new GDLabel("Tree Name");
		Font font = treeNameLabel.getFont();
		font = font.deriveFont(Font.BOLD);
		treeNameLabel.setFont(font);

		nameLabel = new GDLabel("Name Changed");
		nameIconLabel = new GIconLabel(CHANGED_ICON);

		structureLabel = new GDLabel("Structure Changed");
		structureIconLabel = new GIconLabel(CHANGED_ICON);

		namePanel = new JPanel(new PairLayout(0, 5));
		namePanel.add(nameIconLabel);
		namePanel.add(nameLabel);

		structurePanel = new JPanel(new PairLayout(0, 5));
		structurePanel.add(structureIconLabel);
		structurePanel.add(structureLabel);

		JPanel labelPanel = new JPanel();
		labelPanel.setLayout(new BoxLayout(labelPanel, BoxLayout.Y_AXIS));
		labelPanel.add(namePanel);
		labelPanel.add(structurePanel);

		panel.add(treeNameLabel, BorderLayout.NORTH);
		panel.add(labelPanel, BorderLayout.CENTER);
		add(panel);
	}
}
