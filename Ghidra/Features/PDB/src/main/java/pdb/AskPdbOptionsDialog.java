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
package pdb;

import java.awt.BorderLayout;
import java.awt.Component;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.combobox.GComboBox;
import ghidra.app.util.bin.format.pdb.PdbParser;
import ghidra.app.util.pdb.pdbapplicator.PdbApplicatorRestrictions;
import ghidra.util.layout.PairLayout;

class AskPdbOptionsDialog extends DialogComponentProvider {

	private boolean isCanceled;

	private boolean useMsDiaParser;
	private PdbApplicatorRestrictions restrictions = PdbApplicatorRestrictions.NONE;

	/**
	 * Popup PDB loader options
	 * @param parent parent component or null
	 * @param isPdbFile true if file to be loaded is a PDB file, false 
	 * if MsDia XML file.
	 */
	AskPdbOptionsDialog(Component parent, boolean isPdbFile) {
		super("Load PDB Options", true, true, true, false);

		JPanel panel = new JPanel(new BorderLayout(10, 10));
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		JPanel optionsPanel = new JPanel(new PairLayout(10, 10));

		final GComboBox<PdbApplicatorRestrictions> restrictionsCombo =
			new GComboBox<>(PdbApplicatorRestrictions.values());
		restrictionsCombo.setSelectedItem(PdbApplicatorRestrictions.NONE);
		restrictionsCombo.addActionListener(e -> {
			restrictions = (PdbApplicatorRestrictions) restrictionsCombo.getSelectedItem();
		});

		optionsPanel.add(new JLabel("PDB Parser:"));

		if (isPdbFile) {
			useMsDiaParser = false; // Use PDB Universal by default
			if (PdbParser.onWindows) {
				final GComboBox<String> combo =
					new GComboBox<>(new String[] { "PDB Universal", "PDB MSDIA" });
				combo.setSelectedIndex(0);
				restrictionsCombo.setEnabled(!useMsDiaParser);
				combo.addActionListener(e -> {
					useMsDiaParser = (combo.getSelectedIndex() == 1);
					restrictionsCombo.setEnabled(!useMsDiaParser);
					if (useMsDiaParser) {
						restrictionsCombo.setSelectedItem(PdbApplicatorRestrictions.NONE);
					}
				});
				optionsPanel.add(combo);
			}
			else {
				useMsDiaParser = false;
				JLabel label = new JLabel("PDB Universal");
				//label.setForeground(Color.red); // set color to emphasize prototype status
				optionsPanel.add(label);
			}
		}
		else {
			useMsDiaParser = true; // XML file only supported by MsDia parser
			return; // no interaction currently required
		}

		optionsPanel.add(new JLabel("Restrictions:"));
		optionsPanel.add(restrictionsCombo);

		panel.add(optionsPanel, BorderLayout.CENTER);

		addWorkPanel(panel);

		addApplyButton();
		addCancelButton();

		setDefaultButton(applyButton);
		setRememberSize(false);

		DockingWindowManager.showDialog(parent, AskPdbOptionsDialog.this);
	}


	@Override
	protected void applyCallback() {
		isCanceled = false;
		close();
	}

	@Override
	protected void cancelCallback() {
		isCanceled = true;
		close();
	}

	boolean isCanceled() {
		return isCanceled;
	}

	boolean useMsDiaParser() {
		return useMsDiaParser;
	}

	PdbApplicatorRestrictions getApplicatorRestrictions() {
		return restrictions;
	}

}
