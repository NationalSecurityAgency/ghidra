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
package ghidra.features.base.memsearch.gui;

import java.awt.BorderLayout;
import java.awt.FlowLayout;

import javax.swing.*;

import docking.widgets.button.GRadioButton;
import ghidra.app.util.HelpTopics;
import ghidra.features.base.memsearch.scan.Scanner;
import ghidra.util.HelpLocation;
import help.Help;
import help.HelpService;

/**
 * Internal panel of the memory search window that manages the controls for the scan feature. This
 * panel can be added or removed via a toolbar action. Not showing by default.
 */
public class MemoryScanControlPanel extends JPanel {
	private Scanner selectedScanner = Scanner.NOT_EQUALS;
	private boolean hasResults;
	private boolean isBusy;
	private JButton scanButton;

	MemoryScanControlPanel(MemorySearchProvider provider) {
		super(new BorderLayout());
		setBorder(BorderFactory.createEmptyBorder(5, 0, 5, 0));
		add(buildButtonPanel(), BorderLayout.CENTER);
		scanButton = new JButton("Scan Values");
		scanButton.setToolTipText("Refreshes byte values of current results and eliminates " +
			"those that don't meet the selected change criteria");
		HelpService helpService = Help.getHelpService();
		helpService.registerHelp(this, new HelpLocation(HelpTopics.SEARCH, "Scan_Controls"));
		add(scanButton, BorderLayout.WEST);
		scanButton.addActionListener(e -> provider.scan(selectedScanner));
	}

	private JComponent buildButtonPanel() {
		JPanel panel = new JPanel(new FlowLayout());
		ButtonGroup buttonGroup = new ButtonGroup();
		for (Scanner scanner : Scanner.values()) {
			GRadioButton button = new GRadioButton(scanner.getName());
			buttonGroup.add(button);
			panel.add(button);
			button.setSelected(scanner == selectedScanner);
			button.addActionListener(e -> selectedScanner = scanner);
			button.setToolTipText(scanner.getDescription());
		}
		return panel;
	}

	public void setSearchStatus(boolean hasResults, boolean isBusy) {
		this.hasResults = hasResults;
		this.isBusy = isBusy;
		updateScanButton();
	}

	private void updateScanButton() {
		scanButton.setEnabled(canScan());
	}

	private boolean canScan() {
		return hasResults && !isBusy;
	}

}
