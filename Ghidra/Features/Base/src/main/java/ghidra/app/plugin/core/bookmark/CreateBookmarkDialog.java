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
import java.util.Arrays;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.label.GIconLabel;
import docking.widgets.label.GLabel;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.util.HelpLocation;
import ghidra.util.layout.PairLayout;

public class CreateBookmarkDialog extends DialogComponentProvider {

	private BookmarkPlugin plugin;
	private Program program;
	private Address address;

	private GhidraComboBox<String> categoryComboBox;
	private JTextField descriptionTextField;
	private JCheckBox selectionCB;
	private boolean hasSelection;

	CreateBookmarkDialog(BookmarkPlugin plugin, CodeUnit cu, boolean hasSelection) {
		super(BookmarkType.NOTE + " Bookmark", true, true, true, false);

		this.plugin = plugin;
		this.hasSelection = hasSelection;
		this.program = plugin.getCurrentProgram();
		this.address = cu.getMinAddress();

		this.addWorkPanel(buildMainPanel());
		this.addOKButton();
		this.addCancelButton();

		initializeDescription(cu);

		setFocusComponent(categoryComboBox);
		setHelpLocation(new HelpLocation("BookmarkPlugin", "CreateBookmarkDialog"));
	}

	@Override
	public void dispose() {
		this.plugin = null;
		this.program = null;
		this.address = null;
		super.dispose();
	}

	@Override
	protected void okCallback() {

		String cat = categoryComboBox.getText();
		String com = descriptionTextField.getText();

		// Create user Note Bookmark
		if (selectionCB.isSelected()) {
			plugin.setNote(null, cat, com);
		}
		else {
			plugin.setNote(address, cat, com);
		}

		close();
	}

	private JPanel buildMainPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(20, 0, 0, 10));
		panel.add(buildIconLabel(), BorderLayout.WEST);
		panel.add(buildCentralPanel(), BorderLayout.CENTER);
		panel.add(buildCheckboxPanel(), BorderLayout.SOUTH);

		return panel;
	}

	private JPanel buildCheckboxPanel() {
		selectionCB = new GCheckBox("Bookmark Top of Each Selection", hasSelection);
		selectionCB.setEnabled(getSelectionRangeCount() > 1);
		JPanel panel = new JPanel();
		panel.setBorder(BorderFactory.createEmptyBorder(10, 0, 0, 0));
		panel.add(selectionCB);
		return panel;
	}

	private Component buildCentralPanel() {
		JPanel panel = new JPanel(new PairLayout(3, 5));

		categoryComboBox = new GhidraComboBox<>(getModel());
		categoryComboBox.setEditable(true);
		descriptionTextField = new JTextField(20);

		panel.add(new JLabel("Address: ", SwingConstants.RIGHT));
		panel.add(new GLabel(buildLocationString()));

		panel.add(new JLabel("Category: ", SwingConstants.RIGHT));
		panel.add(categoryComboBox);

		panel.add(new JLabel("Description: ", SwingConstants.RIGHT));
		panel.add(descriptionTextField);

		return panel;
	}

	private String buildLocationString() {
		int ranges = getSelectionRangeCount();
		if (ranges > 1) {
			return address.toString() + " (plus " + (ranges - 1) + " more)";
		}
		return address.toString();
	}

	private JLabel buildIconLabel() {
		Icon icon = BookmarkNavigator.NOTE_ICON;
		JLabel imageLabel = new GIconLabel(icon);
		imageLabel.setPreferredSize(
			new Dimension(icon.getIconWidth() + 20, icon.getIconHeight() + 20));
		return imageLabel;
	}

	private int getSelectionRangeCount() {
		if (hasSelection) {
			return plugin.getProgramSelection().getNumAddressRanges();
		}
		return 0;
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

	private void initializeDescription(CodeUnit codeUnit) {
		String defaultComment = getEolComment(codeUnit);

		BookmarkManager bmMgr = program.getBookmarkManager();
		Bookmark[] bookmarks = bmMgr.getBookmarks(address, BookmarkType.NOTE);
		if (bookmarks.length != 0) {
			categoryComboBox.setSelectedItem(bookmarks[0].getCategory());
			descriptionTextField.setText(bookmarks[0].getComment());
		}
		else {
			descriptionTextField.setText(defaultComment);
		}
		descriptionTextField.setCaretPosition(0);
		descriptionTextField.selectAll();
	}

	private String getEolComment(CodeUnit codeUnit) {
		String comment = codeUnit.getComment(CodeUnit.EOL_COMMENT);
		if (comment == null) {
			return "";
		}
		return comment.replace('\n', ' ');
	}
}
