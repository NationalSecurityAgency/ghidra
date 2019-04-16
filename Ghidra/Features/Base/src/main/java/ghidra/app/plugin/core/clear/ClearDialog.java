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
package ghidra.app.plugin.core.clear;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.checkbox.GHtmlCheckBox;
import docking.widgets.label.GLabel;
import ghidra.app.context.ListingActionContext;
import ghidra.util.HelpLocation;

/**
 * Dialog that shows options for "Clear All." User can choose to clear
 * symbols, comments, properties, code, and functions.
 */
public class ClearDialog extends DialogComponentProvider {

	private ClearPlugin plugin;
	private JPanel panel;
	private JCheckBox symbolsCb;
	private JCheckBox commentsCb;
	private JCheckBox propertiesCb;
	private JCheckBox codeCb;
	private JCheckBox functionsCb;
	private JCheckBox registersCb;
	private JCheckBox equatesCb;
	private JCheckBox userReferencesCb;
	private JCheckBox analysisReferencesCb;
	private JCheckBox importReferencesCb;
	private JCheckBox systemReferencesCb;
	private JCheckBox bookmarksCb;
	private ListingActionContext context;

	/**
	 * Constructor
	 */
	ClearDialog(ClearPlugin plugin) {
		super("Clear");
		this.plugin = plugin;
		create();
		addWorkPanel(panel);
		addOKButton();
		addCancelButton();
		setHelpLocation(new HelpLocation(plugin.getName(), "Clear_With_Options"));
	}

	/**
	 * Gets called when the user clicks on the OK Action for the dialog.
	 */
	@Override
	public void okCallback() {
		close();

		ClearOptions opts = new ClearOptions();

		opts.setClearCode(codeCb.isSelected());
		opts.setClearSymbols(symbolsCb.isSelected());
		opts.setClearComments(commentsCb.isSelected());
		opts.setClearProperties(propertiesCb.isSelected());
		opts.setClearFunctions(functionsCb.isSelected());
		opts.setClearRegisters(registersCb.isSelected());
		opts.setClearEquates(equatesCb.isSelected());
		opts.setClearUserReferences(userReferencesCb.isSelected());
		opts.setClearAnalysisReferences(analysisReferencesCb.isSelected());
		opts.setClearImportReferences(importReferencesCb.isSelected());
		opts.setClearDefaultReferences(systemReferencesCb.isSelected());
		opts.setClearBookmarks(bookmarksCb.isSelected());

		plugin.clear(opts, context);
	}

	/**
	 * Gets called when the user clicks on the Cancel Action for the dialog.
	 */
	@Override
	protected void cancelCallback() {
		close();
	}

	/**
	 * Create the main panel.
	 */
	private void create() {

		KeyListener listener = new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					e.consume();
					okCallback();
				}
			}
		};

		panel = new JPanel();
		panel.setLayout(new BorderLayout(10, 10));

		panel.add(new GLabel("Clear Options:"), BorderLayout.NORTH);

		JPanel cbPanel = new JPanel();
		BoxLayout bl = new BoxLayout(cbPanel, BoxLayout.Y_AXIS);
		cbPanel.setLayout(bl);

		symbolsCb = new GCheckBox("Symbols");
		commentsCb = new GHtmlCheckBox(
			"<HTML>Comments <FONT SIZE=\"2\">(does not affect automatic comments)</FONT>");
		commentsCb.setVerticalTextPosition(SwingConstants.TOP);
		propertiesCb = new GCheckBox("Properties");
		codeCb = new GCheckBox("Code");
		functionsCb = new GCheckBox("Functions");
		registersCb = new GCheckBox("Registers");
		equatesCb = new GCheckBox("Equates");
		userReferencesCb = new GCheckBox("User-defined References");
		analysisReferencesCb = new GCheckBox("Analysis References");
		importReferencesCb = new GCheckBox("Import References");
		systemReferencesCb = new GCheckBox("Default References");
		bookmarksCb = new GCheckBox("Bookmarks");

		symbolsCb.setSelected(true);
		symbolsCb.addKeyListener(listener);
		commentsCb.setSelected(true);
		commentsCb.addKeyListener(listener);
		propertiesCb.setSelected(true);
		propertiesCb.addKeyListener(listener);
		codeCb.setSelected(true);
		codeCb.addKeyListener(listener);
		functionsCb.setSelected(true);
		functionsCb.addKeyListener(listener);
		registersCb.setSelected(true);
		registersCb.addKeyListener(listener);
		equatesCb.setSelected(true);
		equatesCb.addKeyListener(listener);
		userReferencesCb.setSelected(true);
		userReferencesCb.addKeyListener(listener);
		analysisReferencesCb.setSelected(true);
		analysisReferencesCb.addKeyListener(listener);
		importReferencesCb.setSelected(true);
		importReferencesCb.addKeyListener(listener);
		systemReferencesCb.setSelected(true);
		systemReferencesCb.addKeyListener(listener);
		bookmarksCb.setSelected(true);
		bookmarksCb.addKeyListener(listener);

		cbPanel.add(symbolsCb);
		cbPanel.add(commentsCb);
		cbPanel.add(propertiesCb);
		cbPanel.add(codeCb);
		cbPanel.add(userReferencesCb);
		cbPanel.add(analysisReferencesCb);
		cbPanel.add(importReferencesCb);
		cbPanel.add(systemReferencesCb);
		cbPanel.add(functionsCb);
		cbPanel.add(registersCb);
		cbPanel.add(equatesCb);
		cbPanel.add(bookmarksCb);

		// if a user clears the code, then we will force them
		// to clear all user references...
		codeCb.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				if (codeCb.isSelected()) {
					userReferencesCb.setSelected(true);
					userReferencesCb.setEnabled(false);
					analysisReferencesCb.setSelected(true);
					analysisReferencesCb.setEnabled(false);
					importReferencesCb.setSelected(true);
					importReferencesCb.setEnabled(false);
					systemReferencesCb.setSelected(true);
					systemReferencesCb.setEnabled(false);
				}
				else {
					userReferencesCb.setEnabled(true);
					analysisReferencesCb.setEnabled(true);
					importReferencesCb.setEnabled(true);
					systemReferencesCb.setEnabled(true);
				}
			}
		});

		userReferencesCb.setEnabled(false);
		analysisReferencesCb.setEnabled(false);
		importReferencesCb.setEnabled(false);
		systemReferencesCb.setEnabled(false);

		// record the checkboxes for later use
		final List<JCheckBox> checkBoxList = new ArrayList<>(10);
		checkBoxList.add(symbolsCb);
		checkBoxList.add(commentsCb);
		checkBoxList.add(propertiesCb);
		checkBoxList.add(codeCb);
		checkBoxList.add(userReferencesCb);
		checkBoxList.add(analysisReferencesCb);
		checkBoxList.add(importReferencesCb);
		checkBoxList.add(systemReferencesCb);
		checkBoxList.add(functionsCb);
		checkBoxList.add(registersCb);
		checkBoxList.add(equatesCb);
		checkBoxList.add(bookmarksCb);

		JPanel buttonPanel = new JPanel();
		JButton selectAllButton = new JButton("Select All");
		selectAllButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				setAllCheckBoxesSelected(true, checkBoxList);
			}
		});

		JButton deselectAllbutton = new JButton("Deselect All");
		deselectAllbutton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				setAllCheckBoxesSelected(false, checkBoxList);
			}
		});

		buttonPanel.add(selectAllButton);
		buttonPanel.add(Box.createHorizontalStrut(10));
		buttonPanel.add(deselectAllbutton);

		JPanel lowerPanel = new JPanel();
		lowerPanel.setLayout(new BoxLayout(lowerPanel, BoxLayout.Y_AXIS));
		JSeparator separator = new JSeparator();

		lowerPanel.setBorder(BorderFactory.createEmptyBorder(0, 10, 5, 10));

		lowerPanel.add(separator);
		lowerPanel.add(buttonPanel);

		JPanel p = new JPanel(new FlowLayout(FlowLayout.CENTER));
		p.add(cbPanel);
		panel.add(p, BorderLayout.CENTER);
		panel.add(lowerPanel, BorderLayout.SOUTH);
	}

	private void setAllCheckBoxesSelected(boolean selected, List<JCheckBox> list) {
		for (JCheckBox checkBox : list) {
			checkBox.setSelected(selected);
		}
	}

	public void setProgramActionContext(ListingActionContext context) {
		this.context = context;
	}
}
