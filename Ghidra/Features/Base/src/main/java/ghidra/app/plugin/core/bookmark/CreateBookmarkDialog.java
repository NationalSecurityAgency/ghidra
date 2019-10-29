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
/*
 * CreateBookmarkDialog.java
 *
 * Created on March 6, 2002, 12:10 PM
 */

package ghidra.app.plugin.core.bookmark;

import java.awt.*;
import java.awt.event.*;
import java.util.Arrays;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.DockingUtils;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.label.GIconLabel;
import docking.widgets.label.GLabel;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.util.HelpLocation;

public class CreateBookmarkDialog extends DialogComponentProvider {

	private BookmarkPlugin plugin;
	private Program program;
	private Address address;

	private JTextField locationTextField;
	private JComboBox<String> categoryComboBox;
	private JTextField categoryTextField;
	private JTextField commentTextField;
	private JCheckBox selectionCB;

	/**
	 * Creates new CreateBookmarkDialog
	 *
	 */
	CreateBookmarkDialog(BookmarkPlugin plugin, CodeUnit cu, boolean hasSelection) {
		super(BookmarkType.NOTE + " Bookmark", true, true, true, false);

		this.plugin = plugin;
		this.program = plugin.getCurrentProgram();
		this.address = cu.getMinAddress();

		this.addWorkPanel(buildWorkPanel(hasSelection));
		this.addOKButton();
		this.addCancelButton();

		this.populateDisplay(cu.getComment(CodeUnit.EOL_COMMENT));

		commentTextField.selectAll();
		setFocusComponent(commentTextField);
		setHelpLocation(new HelpLocation("BookmarkPlugin", "CreateBookmarkDialog"));
	}

	public void dispose() {
		this.plugin = null;
		this.program = null;
		this.address = null;

	}

	@Override
	protected void okCallback() {

		JTextField textField = (JTextField) categoryComboBox.getEditor().getEditorComponent();
		String cat = textField.getText();
		String com = commentTextField.getText();

		// Create user Note Bookmark
		if (selectionCB.isSelected()) {
			plugin.setNote(null, cat, com);
		}
		else {
			plugin.setNote(address, cat, com);
		}

		cancelCallback();
	}

	private JPanel buildWorkPanel(boolean hasSelection) {
		KeyListener listener = new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					Object src = e.getSource();
					if (src == locationTextField) {
						categoryComboBox.requestFocus();
						categoryTextField.requestFocus();
					}
					else if (src == categoryComboBox || src == categoryTextField) {
						commentTextField.requestFocus();
					}
					else if (src == commentTextField) {
						okCallback();
					}
				}
			}
		};

		// Some items in the dialog change depending on whether we have multiple selection
		// ranges, so capture that information here.
		int ranges = 0;
		if (hasSelection) {
			ranges = plugin.getProgramSelection().getNumAddressRanges();
		}

		locationTextField = new JTextField(50);
		locationTextField.setText(address.toString());
		if (hasSelection && ranges > 1) {
			locationTextField.setText(address.toString() + " (plus " + (ranges - 1) + " more)");
		}
		locationTextField.setCaretPosition(0);
		locationTextField.setEditable(false);
		DockingUtils.setTransparent(locationTextField);
		locationTextField.setMinimumSize(locationTextField.getPreferredSize());
		locationTextField.addKeyListener(listener);

		categoryComboBox = new GhidraComboBox<>(getModel());
		categoryComboBox.setEditable(true);
		categoryComboBox.addKeyListener(listener);

		categoryTextField = (JTextField) categoryComboBox.getEditor().getEditorComponent();
		categoryTextField.addKeyListener(listener);

		commentTextField = new JTextField(20);
		commentTextField.addKeyListener(listener);

		selectionCB = new GCheckBox("Bookmark Top of Each Selection", hasSelection);
		selectionCB.setEnabled(false);
		if (hasSelection) {
			selectionCB.setEnabled(ranges > 1);
		}

		JPanel mainPanel = new JPanel(new GridBagLayout());
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.insets = new Insets(5, 5, 0, 5);

		gbc.gridx = 1;
		gbc.gridy = 1;
		gbc.weightx = 0;
		gbc.weighty = 0;
		gbc.fill = GridBagConstraints.NONE;
		gbc.anchor = GridBagConstraints.EAST;
		mainPanel.add(new GLabel("Category: ", SwingConstants.RIGHT), gbc);

		gbc.gridx = 2;
		gbc.gridy = 1;
		gbc.weightx = 0;
		gbc.weighty = 0;
		gbc.fill = GridBagConstraints.HORIZONTAL;
		gbc.anchor = GridBagConstraints.WEST;
		mainPanel.add(categoryComboBox, gbc);

		gbc.gridx = 1;
		gbc.gridy = 0;
		gbc.weightx = 0;
		gbc.weighty = 0;
		gbc.fill = GridBagConstraints.NONE;
		gbc.anchor = GridBagConstraints.EAST;
		mainPanel.add(new GLabel("Address: ", SwingConstants.RIGHT), gbc);

		gbc.gridx = 2;
		gbc.gridy = 0;
		gbc.weightx = 0;
		gbc.weighty = 0;
		gbc.fill = GridBagConstraints.NONE;
		gbc.anchor = GridBagConstraints.WEST;
		mainPanel.add(locationTextField, gbc);

		gbc.gridx = 1;
		gbc.gridy = 2;
		gbc.weightx = 0;
		gbc.weighty = 0;
		gbc.fill = GridBagConstraints.NONE;
		gbc.anchor = GridBagConstraints.EAST;
		mainPanel.add(new GLabel("Description: ", SwingConstants.RIGHT), gbc);

		gbc.gridx = 2;
		gbc.gridy = 2;
		gbc.weightx = 1.0;
		gbc.weighty = 0;
		gbc.fill = GridBagConstraints.HORIZONTAL;
		gbc.anchor = GridBagConstraints.WEST;
		mainPanel.add(commentTextField, gbc);

		ImageIcon icon = BookmarkNavigator.NOTE_ICON;
		JLabel imageLabel = new GIconLabel(icon);
		imageLabel.setPreferredSize(
			new Dimension(icon.getIconWidth() + 20, icon.getIconHeight() + 20));

		JPanel selectionPanel = new JPanel();
		selectionPanel.setBorder(BorderFactory.createEmptyBorder(10, 0, 0, 0));
		selectionPanel.add(selectionCB);

		JPanel workPanel = new JPanel(new BorderLayout());
		workPanel.add(mainPanel, BorderLayout.CENTER);
		workPanel.add(imageLabel, BorderLayout.WEST);
		workPanel.add(selectionPanel, BorderLayout.SOUTH);

		return workPanel;
	}

	/**
	 * Returns a ComboBoxModel populated with a sorted unique list
	 * of all currently defined Bookmark categories.
	 */
	private ComboBoxModel<String> getModel() {
		BookmarkManager mgr = program.getBookmarkManager();
		String[] categories = mgr.getCategories(BookmarkType.NOTE);
		String[] array = new String[categories.length + 1];
		array[0] = "";
		System.arraycopy(categories, 0, array, 1, categories.length);
		Arrays.sort(array);
		return new DefaultComboBoxModel<>(array);
	}

	private void populateDisplay(String defaultComment) {

		if (defaultComment == null) {
			defaultComment = "";
		}
		else {
			defaultComment = defaultComment.replace('\n', ' ');
		}

		BookmarkManager bmMgr = program.getBookmarkManager();
		Bookmark[] bookmarks = bmMgr.getBookmarks(address, BookmarkType.NOTE);
		if (bookmarks.length != 0) {
			categoryComboBox.setSelectedItem(bookmarks[0].getCategory());
			commentTextField.setText(bookmarks[0].getComment());
		}
		else {
			commentTextField.setText(defaultComment);
		}
		commentTextField.setCaretPosition(0);
	}
}
