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
package ghidra.app.plugin.core.diff;

import java.awt.*;
import java.awt.event.*;
import java.util.ArrayList;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.TitledBorder;

import docking.DialogComponentProvider;
import docking.DockingUtils;
import docking.widgets.checkbox.GCheckBox;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramDiffFilter;
import ghidra.program.util.ProgramMemoryComparator;
import ghidra.util.HelpLocation;

/**
 * The ExecuteDiffDialog is used whenever initiating a Program Diff. 
 * It allows the user to specify the types of differences to determine 
 * and the address set to diff.
 */
public class ExecuteDiffDialog extends DialogComponentProvider {

	public static final String DIFF_ACTION = "Diff";
	private static final String TITLE = "Determine Program Differences";
	private static final String ADDRESS_AREA_TITLE = "Address Ranges To Diff";

	private JCheckBox diffBytesCB;
	private JCheckBox diffLabelsCB;
	private JCheckBox diffCodeUnitsCB;
	private JCheckBox diffReferencesCB;
	private JCheckBox diffProgramContextCB;
	private JCheckBox diffCommentsCB;
	private JCheckBox diffBookmarksCB;
	private JCheckBox diffPropertiesCB;
	private JCheckBox diffFunctionsCB;
	private JButton selectAllButton = new JButton("Select All");
	private JButton deselectAllButton = new JButton("Deselect All");
	private JCheckBox limitToSelectionCB;
	private JTextArea addressText;

	private boolean diffBytes;
	private boolean diffLabels;
	private boolean diffCodeUnits;
	private boolean diffReferences;
	private boolean diffProgramContext;
	private boolean diffComments;
	private boolean diffBookmarks;
	private boolean diffProperties;
	private boolean diffFunctions;

	private ProgramDiffFilter diffFilter;
	private JPanel diffPanel;
	private ArrayList<ActionListener> listenerList = new ArrayList<>();
	private boolean limitToSelection;
	private AddressSetView pgm1MemorySet;
	private AddressSetView pgm1SelectionSet;
	private AddressSetView pgm1CompatibleSet;
	private boolean pgmContextEnabled = true;

	/**
	 * @param frame
	 */
	public ExecuteDiffDialog() {
		super(TITLE, true, true, true, false);

		diffPanel = createDiffSettingsPanel();
		init();
		setHelpLocation(new HelpLocation("Diff", "ExecuteDiffDialog"));
	}

	public void configure(Program program1, Program program2,
			AddressSetView currentProgram1SelectionSet, ProgramDiffFilter diff) {

		this.pgm1MemorySet = program1.getMemory();
		this.pgm1SelectionSet = currentProgram1SelectionSet;
		this.pgm1CompatibleSet = ProgramMemoryComparator.getCombinedAddresses(program1, program2);
		setDiffFilter(diff);
		boolean hasSelection =
			((currentProgram1SelectionSet != null) && !currentProgram1SelectionSet.isEmpty());
		setLimitToSelectionEnabled(hasSelection);
		limitToSelection(hasSelection);
		addressText.setText(getAddressText());
	}

	private void init() {
		addWorkPanel(diffPanel);
		addOKButton();
		setOkToolTip("Get the differences and highlight them in the second program.");
		addCancelButton();
	}

	/**
	 * @see ghidra.util.bean.GhidraDialog#okCallback()
	 */
	@Override
	protected void okCallback() {
		if (!hasDiffSelection()) {
			setStatusText("At least one difference type must be checked.");
			Toolkit.getDefaultToolkit().beep();
			return;
		}
		for (int i = 0; i < listenerList.size(); i++) {
			ActionListener listener = listenerList.get(i);
			listener.actionPerformed(new ActionEvent(this, 0, DIFF_ACTION));
		}
		close();
	}

	/**
	 * @see ghidra.util.bean.GhidraDialog#cancelCallback()
	 */
	@Override
	protected void cancelCallback() {
		close();
	}

	JPanel createDiffSettingsPanel() {
		ProgramDiffFilter diff = new ProgramDiffFilter();
		JPanel panel = new JPanel(new BorderLayout());
		JPanel settingsPanel = new JPanel();
		settingsPanel.add(createDiffPanel());
		panel.add(settingsPanel, BorderLayout.NORTH);
		panel.add(createAddressPanel(), BorderLayout.CENTER);
		setDiffFilter(diff);
		return panel;
	}

	/**
	 *  Create a panel for all checkboxes related to applying differences.
	 */
	private JPanel createDiffPanel() {
		JPanel panel = new JPanel();
		TitledBorder border = new TitledBorder("Do Differences On");
		panel.setBorder(border);
		panel.add(createDiffFilterPanel());
		return panel;
	}

	private JPanel createAddressPanel() {
		JPanel addressPanel = new JPanel(new BorderLayout());
		Border border = BorderFactory.createEtchedBorder();
		addressPanel.setBorder(new TitledBorder(border, ADDRESS_AREA_TITLE));
		addressPanel.add(createLimitPanel(), BorderLayout.NORTH);
		addressText = new JTextArea(5, 30);
		addressText.setName("AddressTextArea");
		addressText.setEditable(false);
		DockingUtils.setTransparent(addressText);
		addressText.setText(getAddressText());
		JScrollPane scrolledAddresses = new JScrollPane(addressText);
		addressPanel.add(scrolledAddresses, BorderLayout.CENTER);

		return addressPanel;
	}

	/**
	 *  Create a panel for the checkboxes to indicate the filter settings.
	 */
	private JPanel createLimitPanel() {
		JPanel panel = new JPanel();

		limitToSelectionCB = new GCheckBox("Limit To Selection");
		limitToSelectionCB.setName("LimitToSelectionDiffCB");
		limitToSelectionCB.setToolTipText("Limits the Diff to the selection.");
		limitToSelectionCB.addActionListener(ev -> {
			limitToSelection = limitToSelectionCB.isSelected();
			updateDiffSetText();
			clearStatusText();
		});

		panel.add(limitToSelectionCB);

		return panel;
	}

	/**
	 *  Create a panel for the checkboxes to indicate the filter settings.
	 */
	private JPanel createDiffFilterPanel() {
		JPanel checkBoxPanel = new JPanel();
		checkBoxPanel.setToolTipText(
			"Check the types of differences between the two " +
				"programs that you want detected and highlighted.");

		createBytesCheckBox();
		createLabelsCheckBox();
		createCodeUnitsCheckBox();
		createReferencesCheckBox();
		createProgramContextCheckBox();
		createCommentsCheckBox();
		createBookmarksCheckBox();
		createPropertiesCheckBox();
		createFunctionsCheckBox();

		checkBoxPanel.setLayout(new GridLayout(3, 3, 5, 0));
		checkBoxPanel.add(diffBytesCB);
		checkBoxPanel.add(diffLabelsCB);
		checkBoxPanel.add(diffCodeUnitsCB);
		checkBoxPanel.add(diffReferencesCB);
		checkBoxPanel.add(diffProgramContextCB);
		checkBoxPanel.add(diffCommentsCB);
		checkBoxPanel.add(diffBookmarksCB);
		checkBoxPanel.add(diffPropertiesCB);
		checkBoxPanel.add(diffFunctionsCB);

		JPanel buttonPanel = new JPanel();
		createSelectAllButton();
		buttonPanel.add(selectAllButton);
		createDeselectAllButton();
		buttonPanel.add(deselectAllButton);

		JPanel panel = new JPanel(new BorderLayout());
		panel.add(checkBoxPanel, BorderLayout.CENTER);
		panel.add(buttonPanel, BorderLayout.SOUTH);

		return panel;
	}

	private void createBytesCheckBox() {
		diffBytesCB = new GCheckBox("Bytes", diffBytes);
		diffBytesCB.setName("BytesDiffCB");
		diffBytesCB.setToolTipText("Highlight byte differences.");
		diffBytesCB.addItemListener(event -> {
			diffBytes = (event.getStateChange() == ItemEvent.SELECTED);
			diffFilter.setFilter(ProgramDiffFilter.BYTE_DIFFS, diffBytes);
			clearStatusText();
		});
	}

	private void createLabelsCheckBox() {
		diffLabelsCB = new GCheckBox("Labels", diffLabels);
		diffLabelsCB.setName("LabelsDiffCB");
		diffLabelsCB.setToolTipText("Highlight label differences.");
		diffLabelsCB.addItemListener(event -> {
			diffLabels = (event.getStateChange() == ItemEvent.SELECTED);
			diffFilter.setFilter(ProgramDiffFilter.SYMBOL_DIFFS, diffLabels);
			clearStatusText();
		});
	}

	private void createCodeUnitsCheckBox() {
		diffCodeUnitsCB = new GCheckBox("Code Units", diffCodeUnits);
		diffCodeUnitsCB.setName("CodeUnitsDiffCB");
		diffCodeUnitsCB.setToolTipText(
			"Highlight the instruction, data, " + "and equate differences.");
		diffCodeUnitsCB.addItemListener(event -> {
			diffCodeUnits = (event.getStateChange() == ItemEvent.SELECTED);
			diffFilter.setFilter(ProgramDiffFilter.CODE_UNIT_DIFFS, diffCodeUnits);
			diffFilter.setFilter(ProgramDiffFilter.EQUATE_DIFFS, diffCodeUnits);
			clearStatusText();
		});
	}

	private void createReferencesCheckBox() {
		diffReferencesCB = new GCheckBox("References", diffReferences);
		diffReferencesCB.setName("ReferencesDiffCB");
		diffReferencesCB.setToolTipText("Highlight the reference differences.");
		diffReferencesCB.addItemListener(event -> {
			diffReferences = (event.getStateChange() == ItemEvent.SELECTED);
			diffFilter.setFilter(ProgramDiffFilter.REFERENCE_DIFFS, diffReferences);
			clearStatusText();
		});
	}

	private void createProgramContextCheckBox() {
		diffProgramContextCB = new GCheckBox("Program Context", diffProgramContext);
		diffProgramContextCB.setName("ProgramContextDiffCB");
		diffProgramContextCB.setToolTipText("Highlight the program context register differences.");
		diffProgramContextCB.addItemListener(event -> {
			diffProgramContext = (event.getStateChange() == ItemEvent.SELECTED);
			diffFilter.setFilter(ProgramDiffFilter.PROGRAM_CONTEXT_DIFFS, diffProgramContext);
			clearStatusText();
		});
	}

	private void createCommentsCheckBox() {
		diffCommentsCB = new GCheckBox("Comments", diffComments);
		diffCommentsCB.setName("CommentsDiffCB");
		diffCommentsCB.setToolTipText("Highlight comment differences.");
		diffCommentsCB.addItemListener(event -> {
			diffComments = (event.getStateChange() == ItemEvent.SELECTED);
			diffFilter.setFilter(ProgramDiffFilter.COMMENT_DIFFS, diffComments);
			clearStatusText();
		});
	}

	private void createBookmarksCheckBox() {
		diffBookmarksCB = new GCheckBox("Bookmarks", diffBookmarks);
		diffBookmarksCB.setName("BookmarksDiffCB");
		diffBookmarksCB.setToolTipText(
			"Highlight bookmark differences. " + "(for example, bookmark differences)");
		diffBookmarksCB.addItemListener(event -> {
			diffBookmarks = (event.getStateChange() == ItemEvent.SELECTED);
			diffFilter.setFilter(ProgramDiffFilter.BOOKMARK_DIFFS, diffBookmarks);
			clearStatusText();
		});
	}

	private void createPropertiesCheckBox() {
		diffPropertiesCB = new GCheckBox("Properties", diffProperties);
		diffPropertiesCB.setName("PropertiesDiffCB");
		diffPropertiesCB.setToolTipText("Highlight user defined property differences. " +
				"(for example, Format (space) differences)");
		diffPropertiesCB.addItemListener(event -> {
			diffProperties = (event.getStateChange() == ItemEvent.SELECTED);
			diffFilter.setFilter(ProgramDiffFilter.USER_DEFINED_DIFFS, diffProperties);
			clearStatusText();
		});
	}

	private void createFunctionsCheckBox() {
		diffFunctionsCB = new GCheckBox("Functions", diffFunctions);
		diffFunctionsCB.setName("FunctionsDiffCB");
		diffFunctionsCB.setToolTipText("Highlight function differences.");
		diffFunctionsCB.addItemListener(event -> {
			diffFunctions = (event.getStateChange() == ItemEvent.SELECTED);
			// Functions check box controls both functions and function tags.
			diffFilter.setFilter(ProgramDiffFilter.FUNCTION_DIFFS, diffFunctions);
			diffFilter.setFilter(ProgramDiffFilter.FUNCTION_TAG_DIFFS, diffFunctions);
			clearStatusText();
		});
	}

	private void createSelectAllButton() {
		selectAllButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				setSelectAll(true);
			}
		});
		selectAllButton.setMnemonic('S');
	}

	private void createDeselectAllButton() {
		deselectAllButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				setSelectAll(false);
			}
		});
		deselectAllButton.setMnemonic('D');
	}

	protected void setSelectAll(boolean selected) {
		diffBytesCB.setSelected(selected);
		diffLabelsCB.setSelected(selected);
		diffCodeUnitsCB.setSelected(selected);
		diffReferencesCB.setSelected(selected);
		diffProgramContextCB.setSelected(pgmContextEnabled && selected);
		diffCommentsCB.setSelected(selected);
		diffBookmarksCB.setSelected(selected);
		diffPropertiesCB.setSelected(selected);
		diffFunctionsCB.setSelected(selected);
	}

	private void adjustDiffFilter() {
		diffBytesCB.setSelected(diffBytes);
		diffLabelsCB.setSelected(diffLabels);
		diffCodeUnitsCB.setSelected(diffCodeUnits);
		diffReferencesCB.setSelected(diffReferences);
		diffProgramContextCB.setSelected(pgmContextEnabled && diffProgramContext);
		diffCommentsCB.setSelected(diffComments);
		diffBookmarksCB.setSelected(diffBookmarks);
		diffPropertiesCB.setSelected(diffProperties);
		diffFunctionsCB.setSelected(diffFunctions);

	}

	void setPgmContextEnabled(boolean enable) {
		pgmContextEnabled = enable;
		diffProgramContextCB.setEnabled(enable);
		if (!enable) {
			diffProgramContext = false;
		}
		diffProgramContextCB.setSelected(diffProgramContext);
	}

	/**
	 * Get a copy of the diff tool filter settings.
	 * @return the current diff Filter settings.
	 */
	ProgramDiffFilter getDiffFilter() {
		return new ProgramDiffFilter(diffFilter);
	}

	/**
	 * Sets the diff tool filter settings.
	 * @param filter the new diff Filter settings.
	 */
	void setDiffFilter(ProgramDiffFilter filter) {
		diffFilter = new ProgramDiffFilter(filter);
		diffBytes = diffFilter.getFilter(ProgramDiffFilter.BYTE_DIFFS);
		diffLabels = diffFilter.getFilter(ProgramDiffFilter.SYMBOL_DIFFS);
		diffCodeUnits = diffFilter.getFilter(ProgramDiffFilter.CODE_UNIT_DIFFS);
		diffReferences = diffFilter.getFilter(ProgramDiffFilter.REFERENCE_DIFFS);
		diffProgramContext =
			pgmContextEnabled && diffFilter.getFilter(ProgramDiffFilter.PROGRAM_CONTEXT_DIFFS);
		diffComments = diffFilter.getFilter(ProgramDiffFilter.COMMENT_DIFFS);
		diffBookmarks = diffFilter.getFilter(ProgramDiffFilter.BOOKMARK_DIFFS);
		diffProperties = diffFilter.getFilter(ProgramDiffFilter.USER_DEFINED_DIFFS);
		diffFunctions = diffFilter.getFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		adjustDiffFilter();
	}

	/**
	 * Get the state of the limitToSelection flag.
	 * @return true indicates limitToSelection box is checked.
	 */
	boolean isLimitedToSelection() {
		return limitToSelectionCB.isSelected();
	}

	void limitToSelection(boolean limit) {
		limitToSelection = limit;
		limitToSelectionCB.setSelected(limitToSelection);
		updateDiffSetText();
	}

	void setLimitToSelectionEnabled(boolean enable) {
		limitToSelectionCB.setEnabled(enable);
	}

	private void updateDiffSetText() {
		AddressSetView pgm1AddressSet = getAddressSet();
		addressText.setText(getAddressText());
		setOkEnabled(pgm1AddressSet != null && !pgm1AddressSet.isEmpty());
	}

	/**
	 * Get the current address set for the diff depending on whether or not the 
	 * Diff is limited to a selection.
	 */
	AddressSetView getAddressSet() {
		if (isLimitedToSelection()) {
			return new AddressSet(pgm1SelectionSet);
		}
//		if (pgm1CompatibleSet.equals(pgm1MemorySet)) {
//			return null;
//		}
		return new AddressSet(pgm1CompatibleSet);
	}

	private String getAddressText() {
		AddressSetView addrs = getAddressSet();
		StringBuffer addrStr = new StringBuffer();
		if ((addrs == null) || addrs.equals(pgm1MemorySet)) {
			return "Entire Program";
		}
		for (AddressRange range : addrs) {
			addrStr.append(range.toString() + "\n");
		}
		return addrStr.toString();
	}

	public void addActionListener(ActionListener listener) {
		listenerList.add(listener);
	}

	public void removeActionListener(ActionListener listener) {
		listenerList.remove(listener);
	}

	/**
	 * Return true if at least one of the checkboxes for the filter
	 * has been selected.
	 */
	boolean hasDiffSelection() {
		return (diffBytes || diffLabels || diffCodeUnits || diffProgramContext || diffReferences ||
			diffComments || diffBookmarks || diffProperties || diffFunctions);
	}

	/**
	 * Return true if all types of differences are being determined.
	 */
	boolean isMarkingAllDiffs() {
		return (diffBytes && diffLabels && diffCodeUnits &&
			((!pgmContextEnabled) || diffProgramContext) && diffReferences && diffComments &&
			diffBookmarks && diffProperties && diffFunctions);
	}

}
