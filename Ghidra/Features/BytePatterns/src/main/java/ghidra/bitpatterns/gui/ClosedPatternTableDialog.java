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

import java.awt.BorderLayout;
import java.awt.Component;
import java.util.List;

import javax.swing.ImageIcon;
import javax.swing.JPanel;

import docking.*;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.table.threaded.GThreadedTablePanel;
import ghidra.bitpatterns.info.ContextRegisterFilter;
import ghidra.bitpatterns.info.PatternType;
import ghidra.util.HelpLocation;
import ghidra.util.bytesearch.DittedBitSequence;
import resources.ResourceManager;

/**
 * This provider is used to display tables containing patterns found by
 * the pattern miner.
 */
public class ClosedPatternTableDialog extends DialogComponentProvider {

	private DockingAction sendToClipboardAction;
	private static final String TITLE = "Closed Patterns";
	private ClosedPatternTableModel closedPatternTableModel;
	private GThreadedTablePanel<ClosedPatternRowObject> tablePanel;
	private JPanel mainPanel;
	private FunctionBitPatternsExplorerPlugin plugin;
	private PatternType type;
	private ContextRegisterFilter cRegFilter;

	/**
	 * @param plugin plugin
	 * @param rowObjects closed patterns to display 
	 * @param parent parent component
	 * @param type {@link PatternType} of sequences mined for the closed patterns
	 * @param cRegFilter context register filter used to filter sequences
	 */
	public ClosedPatternTableDialog(FunctionBitPatternsExplorerPlugin plugin,
			List<ClosedPatternRowObject> rowObjects, Component parent, PatternType type,
			ContextRegisterFilter cRegFilter) {
		super(TITLE, false, true, true, false);
		this.plugin = plugin;
		closedPatternTableModel = createClosedPatternTable(rowObjects);
		this.type = type;
		this.cRegFilter = cRegFilter;
		mainPanel = createMainPanel();

		addWorkPanel(mainPanel);
		addCancelButton();
		cancelButton.setText("Dismiss");
		addClipboardAction();
		this.setDefaultSize(1200, 800);
		HelpLocation helpLocation = new HelpLocation("FunctionBitPatternsExplorerPlugin",
			"Mining_Closed_Sequential_Patterns");
		setHelpLocation(helpLocation);
		DockingWindowManager.showDialog(parent, this);

	}

	private JPanel createMainPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		tablePanel = new GThreadedTablePanel<>(closedPatternTableModel);
		panel.add(tablePanel, BorderLayout.CENTER);
		return panel;
	}

	private ClosedPatternTableModel createClosedPatternTable(
			List<ClosedPatternRowObject> rowObjects) {
		return new ClosedPatternTableModel(rowObjects, plugin.getTool());
	}

	private void addClipboardAction() {
		sendToClipboardAction = new DockingAction("Send Selected Sequences to Clipboard", TITLE) {

			@Override
			public void actionPerformed(ActionContext context) {
				List<ClosedPatternRowObject> rows =
					closedPatternTableModel.getLastSelectedObjects();
				for (ClosedPatternRowObject row : rows) {
					DittedBitSequence seq = new DittedBitSequence(row.getDittedString(), true);
					PatternInfoRowObject pattern = new PatternInfoRowObject(type, seq, cRegFilter);
					plugin.addPattern(pattern);
				}
				plugin.updateClipboard();
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return true;
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return (!closedPatternTableModel.getLastSelectedObjects().isEmpty());
			}

		};
		ImageIcon icon = ResourceManager.loadImage("images/2rightarrow.png");
		sendToClipboardAction.setPopupMenuData(
			new MenuData(new String[] { "Send Selected Sequences to Clipboard" }, icon));
		sendToClipboardAction.setDescription(
			"Sends the currently selected sequences to the clipboard");
		this.addAction(sendToClipboardAction);
	}

	@Override
	public void close() {
		super.close();
		tablePanel.dispose();
	}
}
