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
package ghidra.feature.vt.gui.provider.matchtable;

import java.awt.BorderLayout;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import docking.widgets.checkbox.GCheckBox;
import ghidra.feature.vt.api.correlator.program.ImpliedMatchProgramCorrelator;
import ghidra.feature.vt.api.correlator.program.ManualMatchProgramCorrelator;
import ghidra.feature.vt.api.impl.VTProgramCorrelatorInfo;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.api.main.VTMatchSet;
import ghidra.feature.vt.api.util.VTAbstractProgramCorrelatorFactory;
import ghidra.feature.vt.gui.filters.CheckBoxBasedAncillaryFilter;
import ghidra.feature.vt.gui.filters.CheckBoxInfo;
import ghidra.util.classfinder.ClassSearcher;

public class AlgorithmFilter extends CheckBoxBasedAncillaryFilter<VTMatch> {

	public AlgorithmFilter() {
		super("Algorithm");
	}

	@Override
	protected JPanel createFilterPanel(JPanel checkBoxPanel) {

		JButton selectButton = new JButton("Select All");
		selectButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				for (CheckBoxInfo<VTMatch> info : checkBoxInfos) {
					info.getCheckBox().setSelected(true);
				}
			}
		});

		JButton deselectButton = new JButton("Deselect All");
		deselectButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				for (CheckBoxInfo<VTMatch> info : checkBoxInfos) {
					info.getCheckBox().setSelected(false);
				}
			}
		});

		JPanel southPanel = new JPanel();
		southPanel.add(selectButton);
		southPanel.add(deselectButton);

		JPanel parentPanel = new JPanel(new BorderLayout());
		parentPanel.add(checkBoxPanel, BorderLayout.CENTER);
		parentPanel.add(southPanel, BorderLayout.SOUTH);

		return parentPanel;
	}

	@Override
	protected void createCheckBoxInfos() {
		List<String> algorithmNames = getKnowAlgorithms();

		ItemListener listener = new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				fireStatusChanged(getFilterStatus());
			}
		};

		for (String name : algorithmNames) {
			GCheckBox checkBox = new GCheckBox(name, true);
			checkBox.addItemListener(listener);
			CheckBoxInfo<VTMatch> info = new AlgorithmNameCheckBoxInfo(checkBox, name);
			checkBoxInfos.add(info);
		}
	}

	private List<String> getKnowAlgorithms() {
		List<String> list = new ArrayList<>();

		// add the manual match correlator, which doesn't have a factory, since it is only through an action.
		list.add(ManualMatchProgramCorrelator.NAME);
		list.add(ImpliedMatchProgramCorrelator.NAME);

		List<VTAbstractProgramCorrelatorFactory> instances =
			ClassSearcher.getInstances(VTAbstractProgramCorrelatorFactory.class);
		for (VTAbstractProgramCorrelatorFactory factory : instances) {
			list.add(factory.getName());
		}
		return list;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class AlgorithmNameCheckBoxInfo extends CheckBoxInfo<VTMatch> {

		private final String algorithmName;

		public AlgorithmNameCheckBoxInfo(JCheckBox checkBox, String name) {
			super(checkBox);
			this.algorithmName = name;
		}

		@Override
		public boolean matchesStatus(VTMatch match) {
			if (!isSelected()) {
				return false;
			}
			VTMatchSet matchSet = match.getMatchSet();
			VTProgramCorrelatorInfo info = matchSet.getProgramCorrelatorInfo();
			String matchCorrelatorName = info.getName();
			return matchCorrelatorName.equals(algorithmName);
		}
	}

}
