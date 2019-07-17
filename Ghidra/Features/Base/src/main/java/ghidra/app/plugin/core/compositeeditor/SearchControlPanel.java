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
package ghidra.app.plugin.core.compositeeditor;

import java.awt.*;

import javax.swing.*;
import javax.swing.border.BevelBorder;
import javax.swing.border.Border;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.widgets.EmptyBorderButton;
import docking.widgets.label.GLabel;
import resources.ResourceManager;

public class SearchControlPanel extends JPanel {

	private static final Icon NEXT_ICON = ResourceManager.getScaledIcon(
		ResourceManager.loadImage("images/go-down.tango.16.png"), 16, 16);
	private static final Icon PREV_ICON = ResourceManager.getScaledIcon(
		ResourceManager.loadImage("images/go-up.tango.16.png"), 16, 16);
	private CompositeEditorPanel editorPanel;
	private JTextField textField;

	private EmptyBorderButton searchNext;
	private EmptyBorderButton searchPrevious;

	public SearchControlPanel(CompositeEditorPanel editorPanel) {
		this.editorPanel = editorPanel;

		setLayout(new BorderLayout());
		add(new GLabel("Search: "), BorderLayout.WEST);
		textField = new JTextField(20);
		add(textField, BorderLayout.CENTER);
		add(buildButtonPanel(), BorderLayout.EAST);

		Border bevel = BorderFactory.createBevelBorder(BevelBorder.LOWERED);
		Border spacer = BorderFactory.createEmptyBorder(4, 10, 5, 10);
		setBorder(BorderFactory.createCompoundBorder(bevel, spacer));

		textField.addActionListener(e -> search(true));
		textField.setToolTipText(
			"Search text is not case sensitive.  Press <Return> to search forward.");

		textField.getDocument().addDocumentListener(new DocumentListener() {

			@Override
			public void removeUpdate(DocumentEvent e) {
				updateSearchButtons();
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				updateSearchButtons();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				updateSearchButtons();
			}

			private void updateSearchButtons() {
				boolean hasText = textField.getText().length() > 0;
				searchNext.setEnabled(hasText);
				searchPrevious.setEnabled(hasText);
			}
		});

		searchNext.setEnabled(false);
		searchPrevious.setEnabled(false);
	}

	private Component buildButtonPanel() {
		JPanel panel = new JPanel(new GridLayout(1, 2));

		searchNext = new EmptyBorderButton(NEXT_ICON);
		searchPrevious = new EmptyBorderButton(PREV_ICON);
		panel.add(searchNext);
		panel.add(searchPrevious);

		searchNext.addActionListener(e -> search(true));
		searchPrevious.addActionListener(e -> search(false));
		searchNext.setFocusable(false);
		searchPrevious.setFocusable(false);
		searchNext.setToolTipText("Search forward");
		searchPrevious.setToolTipText("Search backward");
		return panel;

	}

	protected void search(boolean b) {
		String searchText = textField.getText().trim();
		if (searchText.length() > 0) {
			editorPanel.search(searchText, b);
		}
	}

}
