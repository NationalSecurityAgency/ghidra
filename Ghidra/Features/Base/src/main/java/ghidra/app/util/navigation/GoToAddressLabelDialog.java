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
package ghidra.app.util.navigation;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.LinkedList;
import java.util.List;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.event.HyperlinkEvent;
import javax.swing.event.HyperlinkListener;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.tool.ToolConstants;
import docking.widgets.HyperlinkComponent;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GhidraComboBox;
import ghidra.GhidraOptions;
import ghidra.app.nav.Navigatable;
import ghidra.app.services.*;
import ghidra.app.util.HelpTopics;
import ghidra.framework.options.Options;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.util.HelpLocation;
import ghidra.util.task.TaskMonitorComponent;

public class GoToAddressLabelDialog extends DialogComponentProvider implements GoToServiceListener {

	//////////////////////////////////////////////////////////////////////
	//                                                                  //
	// Static methods and fields                                        //
	//                                                                  //
	//////////////////////////////////////////////////////////////////////

	private static final String DIALOG_TITLE = "Go To ...";

	private static final String ANCHOR_NAME = "EXPRESSION";
	private static final int DEFAULT_MAX_GOTO_ENTRIES = 10;

	//////////////////////////////////////////////////////////////////////
	//                                                                  //
	// Instance fields                                                  //
	//                                                                  //
	//////////////////////////////////////////////////////////////////////

	private Plugin plugin;
	private JPanel mainPanel;
	private Address currentAddress;
	private GhidraComboBox<String> comboBox;
	private List<String> history = new LinkedList<>();
	private JCheckBox caseSensitiveBox;

	private boolean cStyleInput = false;
	private GoToService goToService;

	private boolean goToMemory = true;

	private Navigatable navigatable;

	private HyperlinkComponent hyperlink;

	private JCheckBox includeDynamicBox;

	//////////////////////////////////////////////////////////////////////
	//                                                                  //
	// Constructor                                                      //
	//                                                                  //
	//////////////////////////////////////////////////////////////////////

	public GoToAddressLabelDialog(GoToService gotoService, Plugin plugin) {
		super(DIALOG_TITLE, true, true, true, true);
		this.goToService = gotoService;
		setHelpLocation(new HelpLocation(HelpTopics.NAVIGATION, "Go_To_Address_Label"));
		this.plugin = plugin;
		addWorkPanel(buildMainPanel());
		addOKButton();
		addCancelButton();
		setMinimumSize(getPreferredSize());
	}

	/**
	 * Popup up the dialog in the center of the tool.
	 */
	public void show(Navigatable nav, Address addr, PluginTool tool) {
		this.navigatable = nav;
		currentAddress = addr;
		clearStatusText();
		GoToOverrideService override = goToService.getOverrideService();
		if (override != null) {
			JComponent comp = override.getOverrideComponent();
			if (comp != null) {
				mainPanel.add(comp, BorderLayout.SOUTH);
			}
		}
		setDialogEnabled(true);
		tool.showDialog(this);
	}

	@Override
	// overridden to make sure the combo box text is selected
	protected void dialogShown() {
		// make sure the current item is selected
		initializeContents();
	}

	@Override
	public void close() {
		TaskMonitorComponent monitor = getTaskMonitorComponent();
		if (monitor != null) {
			monitor.cancel();
		}
		clearAll();
		super.close();
	}

	@Override
	public void gotoCompleted(String queryString, boolean foundResults) {
		navigatable = null;
		setDialogEnabled(true);
		if (foundResults) {
			close();
			addToHistory(queryString);
		}
		else {
			setStatusText("No results for " + queryString);
			initializeContents();
		}
	}

	@Override
	public void gotoFailed(Exception exc) {
		navigatable = null;
		setDialogEnabled(true);
		setStatusText("ERROR: " + exc.getMessage());
		initializeContents();
	}

	private void initializeContents() {
		if (goToMemory) {
			JTextField field = (JTextField) comboBox.getEditor().getEditorComponent();
			field.selectAll();
			field.requestFocus();
		}
		else {
			comboBox.setSelectedItem(null);
		}
	}

	/**
	 * Builds the main panel for this dialog.
	 */
	final protected JPanel buildMainPanel() {

		JPanel inner = new JPanel();
		GridBagLayout gl = new GridBagLayout();
		inner.setLayout(gl);
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.fill = GridBagConstraints.BOTH;
		gbc.anchor = GridBagConstraints.WEST;
		gbc.weightx = 1;
		gbc.gridwidth = 2;
		gbc.insets = new Insets(5, 5, 5, 5);

		hyperlink = new HyperlinkComponent("<html>Enter an address, label or " + "<a href=\"" +
			ANCHOR_NAME + "\">expression</a>:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;");
		DockingWindowManager.setHelpLocation(hyperlink,
			new HelpLocation(HelpTopics.NAVIGATION, "gotoexpression"));

		hyperlink.addHyperlinkListener(ANCHOR_NAME, new HyperlinkListener() {
			@Override
			public void hyperlinkUpdate(HyperlinkEvent e) {
				if (e.getEventType() != HyperlinkEvent.EventType.ACTIVATED) {
					return;
				}
				showExpressionHelp();
			}
		});
		inner.add(hyperlink);
		inner.add(hyperlink, gbc);

		comboBox = new GhidraComboBox<>();
		comboBox.setEditable(true);
		comboBox.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				okCallback();
			}
		});
		gbc.insets = new Insets(2, 5, 2, 0);
		gbc.gridx = 0;
		gbc.gridy = 1;
		gbc.gridwidth = 2;
		inner.add(comboBox, gbc);

		caseSensitiveBox = new GCheckBox("Case sensitive", false);
		gbc.gridy = 2;
		gbc.gridwidth = 1;
		inner.add(caseSensitiveBox, gbc);

		includeDynamicBox = new GCheckBox("Dynamic labels", true);
		includeDynamicBox.setToolTipText("Include dynamic lables in the search (slower)");
		gbc.gridx = 1;
		inner.add(includeDynamicBox, gbc);

		mainPanel = new JPanel(new BorderLayout());
		Border emptyBorder = BorderFactory.createEmptyBorder(5, 5, 0, 5);
		mainPanel.setBorder(emptyBorder);
		mainPanel.add(inner, BorderLayout.NORTH);

		return mainPanel;
	}

	protected void showExpressionHelp() {
		DockingWindowManager.getHelpService().showHelp(hyperlink, false, hyperlink);

	}

	private void writeHistory(SaveState saveState) {
		String[] strs = new String[history.size()];
		strs = history.toArray(strs);
		saveState.putStrings("GO_TO_HISTORY", strs);
	}

	private void readHistory(SaveState saveState) {
		String[] strs = saveState.getStrings("GO_TO_HISTORY", null);
		if (strs != null) {
			for (int i = 0; i < strs.length; i++) {
				if (!history.contains(strs[i])) {
					history.add(strs[i]);
				}
			}
			truncateHistoryAsNeeded();
			updateCombo();
		}
	}

	public void readConfigState(SaveState saveState) {
		readHistory(saveState);

		boolean caseSensitive = saveState.getBoolean("CASE_SENSITIVE", false);
		caseSensitiveBox.setSelected(caseSensitive);
		boolean includeDynamic = saveState.getBoolean("INCLUDE_DYNAMIC", true);
		includeDynamicBox.setSelected(includeDynamic);
	}

	public void writeConfigState(SaveState saveState) {
		writeHistory(saveState);
		saveState.putBoolean("CASE_SENSITIVE", caseSensitiveBox.isSelected());
		saveState.putBoolean("INCLUDE_DYNAMIC", includeDynamicBox.isSelected());
	}

	//////////////////////////////////////////////////////////////////////
	//                                                                  //
	// Overridden GhidraDialog methods                                  //
	//                                                                  //
	//////////////////////////////////////////////////////////////////////

	@Override
	public final void okCallback() {
		String input = comboBox.getText().trim();
		if (cStyleInput) {
			input = parseNumber(input);
		}

		if (input.length() == 0) {
			escapeCallback();
			return;
		}

		setDialogEnabled(false);
		setStatusText("Searching... Please wait.");
		goToService.goToQuery(navigatable, currentAddress,
			new QueryData(input, caseSensitiveBox.isSelected(), includeDynamicBox.isSelected()),
			this, getTaskMonitorComponent());
	}

	private void setDialogEnabled(boolean enable) {
		setOkEnabled(enable);
		caseSensitiveBox.setEnabled(enable);
//    	setCancelEnabled(enable);
		if (enable) {
			setCursor(Cursor.getDefaultCursor());
		}
		else {
			setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
		}

	}

	private String parseNumber(String input) {
		try {
			if (input.startsWith("0x")) {
				return input;
			}
			if (input.startsWith("0")) {
				return Integer.toString(Integer.parseInt(input, 8), 16);
			}
			if (input.toLowerCase().endsWith("b")) {
				return Integer.toString(Integer.parseInt(input.substring(0, input.length() - 1), 2),
					16);
			}
			return Integer.toString(Integer.parseInt(input, 10), 16);
		}
		catch (Exception e) {
			return input;
		}
	}

	//////////////////////////////////////////////////////////////////////

	public void maxEntrysChanged() {
		truncateHistoryAsNeeded();
		updateCombo();
	}

	private void truncateHistoryAsNeeded() {
		Options opt = plugin.getTool().getOptions(ToolConstants.TOOL_OPTIONS);
		int maxEntries =
			opt.getInt(GhidraOptions.OPTION_MAX_GO_TO_ENTRIES, DEFAULT_MAX_GOTO_ENTRIES);
		int historySize = history.size();

		if (historySize > maxEntries) {
			int numToRemove = historySize - maxEntries;

			for (int i = 0; i < numToRemove; i++) {
				history.remove(history.size() - 1);
			}
		}
	}

	//////////////////////////////////////////////////////////////////////

	private void addToHistory(String input) {
		history.remove(input);
		history.add(0, input);
		truncateHistoryAsNeeded();
		updateCombo();
	}

	private void updateCombo() {
		String[] historyElements = new String[history.size()];
		history.toArray(historyElements);
		comboBox.setModel(new DefaultComboBoxModel<>(historyElements));
	}

	private void clearAll() {
		comboBox.setSelectedItem("");
		setStatusText("");
	}

	public void setCaseSensitive(boolean b) {
		caseSensitiveBox.setSelected(false);
	}

	public List<String> getHistory() {
		return history;
	}

	public void setCStyleInput(boolean cStyleInput) {
		this.cStyleInput = cStyleInput;
	}

	public void setMemory(boolean goToMemory) {
		this.goToMemory = goToMemory;
	}

	// JUnits
	public void setText(String text) {
		try {
			Component comp = comboBox.getEditor().getEditorComponent();
			((JTextField) comp).setText(text);
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}
