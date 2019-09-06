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
package ghidra.bitpatterns.gui;

import java.awt.*;
import java.util.List;

import javax.swing.*;
import javax.swing.border.TitledBorder;

import docking.*;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.table.GFilterTable;
import ghidra.bitpatterns.info.*;
import ghidra.util.HelpLocation;
import ghidra.util.bytesearch.DittedBitSequence;
import resources.ResourceManager;

/**
 * This is a base class for providers which allow the user to analyze sequences of bytes.
 */
public abstract class ByteSequenceAnalyzerProvider extends DialogComponentProvider {

	protected ByteSequenceTableModel byteSequenceTable;
	protected FunctionBitPatternsExplorerPlugin plugin;
	protected JPanel mainPanel;
	private JPanel infoPanel;
	private JTextField mergedSeqTextField;
	private JTextField bitsOfCheckField;
	private JTextField noteField;
	private DittedBitSequence merged;
	protected PatternType type;
	protected ContextRegisterFilter cRegFilter;
	protected String note;
	protected String title;
	private boolean mergedToSend = false;

	private DockingAction sendSelectedToClipboardAction;
	private DockingAction mergeAction;
	private DockingAction sendMergedToClipboardAction;

	/**
	 * Creates a dialog for analyzing sequences of bytes.
	 * @param title dialog title
	 * @param plugin plugin
	 * @param rowObjects row objects representing sequences to analyze
	 * @param parent parent component
	 * @param type type of sequences
	 * @param cRegFilter context register filter
	 * @param note note for clipboard
	 */
	public ByteSequenceAnalyzerProvider(String title, FunctionBitPatternsExplorerPlugin plugin,
			List<ByteSequenceRowObject> rowObjects, Component parent, PatternType type,
			ContextRegisterFilter cRegFilter, String note) {
		super(title, false, true, true, false);
		this.plugin = plugin;
		this.type = type;
		this.cRegFilter = cRegFilter;
		this.note = note;
		this.title = title;
		byteSequenceTable = createByteSequenceTable(plugin, rowObjects);
		infoPanel = createInfoPanel();
		mainPanel = createMainPanel();

		addWorkPanel(mainPanel);
		addCancelButton();
		addSendSelectedToClipboardAction();
		addMergeAction();
		addSendMergedToClipboardAction();
		cancelButton.setText("Dismiss");
		HelpLocation helpLocation =
			new HelpLocation("FunctionBitPatternsExplorerPlugin", "Analyzing_Byte_Sequences");
		setHelpLocation(helpLocation);
		this.setDefaultSize(1200, 800);
		DockingWindowManager.showDialog(parent, this);

	}

	private JPanel createMainPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.add(infoPanel, BorderLayout.NORTH);
		GFilterTable<ByteSequenceRowObject> filterTable = new GFilterTable<>(byteSequenceTable);
		panel.add(filterTable, BorderLayout.CENTER);
		return panel;
	}

	private JPanel createInfoPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		mergedSeqTextField = new JTextField(60);
		mergedSeqTextField.setEditable(false);
		TitledBorder lubBorder = new TitledBorder("Merged Selections");
		mergedSeqTextField.setBorder(lubBorder);

		bitsOfCheckField = new JTextField(5);
		bitsOfCheckField.setEditable(false);
		TitledBorder bitsOfCheckBorder = new TitledBorder("Bits of Check");
		bitsOfCheckField.setBorder(bitsOfCheckBorder);

		noteField = new JTextField(60);
		noteField.setText(note);
		noteField.setEditable(true);
		TitledBorder noteBorder = new TitledBorder("Note");
		noteField.setBorder(noteBorder);

		panel.add(mergedSeqTextField, BorderLayout.NORTH);
		panel.add(bitsOfCheckField, BorderLayout.CENTER);
		panel.add(noteField, BorderLayout.SOUTH);
		return panel;
	}

	private void addSendSelectedToClipboardAction() {
		sendSelectedToClipboardAction = new DockingAction("Send Selected to Clipboard", title) {
			@Override
			public void actionPerformed(ActionContext context) {
				List<ByteSequenceRowObject> rows = byteSequenceTable.getLastSelectedObjects();
				for (ByteSequenceRowObject row : rows) {
					DittedBitSequence seq = new DittedBitSequence(row.getSequence(), true);
					PatternInfoRowObject pattern = new PatternInfoRowObject(type, seq, cRegFilter);
					pattern.setNote(row.getDisassembly());
					plugin.addPattern(pattern);
				}
				plugin.updateClipboard();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				List<ByteSequenceRowObject> rows = byteSequenceTable.getLastSelectedObjects();
				if (rows == null) {
					return false;
				}
				if (rows.isEmpty()) {
					return false;
				}
				return true;
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return true;
			}
		};

		ImageIcon icon = ResourceManager.loadImage("images/2rightarrow.png");
		sendSelectedToClipboardAction.setPopupMenuData(
			new MenuData(new String[] { "Send Selected to Clipboard" }, icon));
		sendSelectedToClipboardAction.setDescription(
			"Creates patterns for the currently-selected strings of " +
				"bytes and sends them to the clipboard");
		sendSelectedToClipboardAction.setHelpLocation(
			new HelpLocation("FunctionBitPatternsExplorerPlugin", "Analyzing_Byte_Sequences"));
		this.addAction(sendSelectedToClipboardAction);
	}

	private void addMergeAction() {
		mergeAction = new DockingAction("Merge Selected Rows", title) {
			@Override
			public void actionPerformed(ActionContext context) {
				merged = byteSequenceTable.mergeSelectedRows();
				if (merged == null) {
					return;
				}
				mergedSeqTextField.setText(merged.getHexString());
				bitsOfCheckField.setText(Integer.toString(merged.getNumFixedBits()));
				mergedSeqTextField.setBackground(Color.WHITE);
				bitsOfCheckField.setBackground(Color.WHITE);
				noteField.setBackground(Color.WHITE);
				mergedToSend = true;
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return true;
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return (!byteSequenceTable.getLastSelectedObjects().isEmpty());
			}

		};
		ImageIcon icon = ResourceManager.loadImage("images/xor.png");
		mergeAction.setPopupMenuData(new MenuData(new String[] { "Merge Selected Rows" }, icon));
		mergeAction.setDescription("Merges the currently selected rows");
		mergeAction.setHelpLocation(
			new HelpLocation("FunctionBitPatternsExplorerPlugin", "Analyzing_Byte_Sequences"));
		this.addAction(mergeAction);
	}

	private void addSendMergedToClipboardAction() {
		sendMergedToClipboardAction = new DockingAction("Send Merged to Clipboard", title) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (merged != null) {
					PatternInfoRowObject mergedInfo =
						new PatternInfoRowObject(type, merged, cRegFilter);
					note = noteField.getText();
					mergedInfo.setNote(note);
					plugin.addPattern(mergedInfo);
					plugin.updateClipboard();
					mergedSeqTextField.setBackground(Color.lightGray);
					bitsOfCheckField.setBackground(Color.LIGHT_GRAY);
					noteField.setBackground(Color.LIGHT_GRAY);
					mergedToSend = false;
				}
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return true;
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return mergedToSend;

			}

		};
		ImageIcon icon = ResourceManager.loadImage("images/smallRightArrow.png");
		sendMergedToClipboardAction.setPopupMenuData(
			new MenuData(new String[] { "Send Merged to Clipboard" }, icon));
		sendMergedToClipboardAction.setDescription("Sends the Merge Patterns to the Clipboard");
		sendMergedToClipboardAction.setHelpLocation(
			new HelpLocation("FunctionBitPatternsExplorerPlugin", "Analyzing_Byte_Sequences"));
		this.addAction(sendMergedToClipboardAction);

	}

	/**
	 * Creates the table to byte sequences to analyze
	 * @param FBPplugin plugin
	 * @param rows row objects containing sequences to analyze
	 * @return
	 */
	abstract ByteSequenceTableModel createByteSequenceTable(
			FunctionBitPatternsExplorerPlugin FBPplugin, List<ByteSequenceRowObject> rows);
}
