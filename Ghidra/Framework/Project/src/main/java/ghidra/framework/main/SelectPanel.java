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
package ghidra.framework.main;

import java.awt.GridLayout;
import java.awt.event.ActionListener;

import javax.swing.*;
import javax.swing.border.Border;

/**
 * A simple panel with buttons for selecting and de-selecting items
 */
public class SelectPanel extends JPanel {

	private final static String SELECT_ALL = "Select All";
	private final static String DESELECT_ALL = "Select None";

	public SelectPanel(ActionListener selectAllCallback, ActionListener deselectAllCallback) {

		JButton selectAllButton = new JButton(SELECT_ALL);
		selectAllButton.setMnemonic('A');
		selectAllButton.addActionListener(selectAllCallback);
		JButton deselectAllButton = new JButton(DESELECT_ALL);
		deselectAllButton.setMnemonic('N');
		deselectAllButton.addActionListener(deselectAllCallback);

		JPanel subPanel = new JPanel();
		int buttonGap = 10;
		subPanel.setLayout(new GridLayout(0, 1, 0, buttonGap));

		int top = 8;
		int side = 20;
		Border inside = BorderFactory.createEmptyBorder(top, side, top, side);
		subPanel.setBorder(inside);

		subPanel.add(selectAllButton);
		subPanel.add(deselectAllButton);
		add(subPanel);

	}
}
