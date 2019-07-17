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
package ghidra.feature.vt.gui.wizard;

import ghidra.feature.vt.api.main.VTProgramCorrelatorFactory;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.framework.options.EditorStateFactory;
import ghidra.framework.options.Options;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.layout.MiddleLayout;
import ghidra.util.layout.VerticalLayout;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JPanel;
import javax.swing.JScrollPane;

import util.CollectionUtils;
import docking.options.editor.OptionsEditorPanel;
import docking.wizard.*;

public class OptionsPanel extends AbstractMageJPanel<VTWizardStateKey> {

	private static final Dimension DEFAULT_PREFERRED_SIZE = new Dimension(650, 350);

	private List<OptionsEditorPanel> optionsEditorPanelList;
	private List<VTOptions> optionsList = null;
	private PropertyChangeListener propertyChangeListener = new PropertyChangeListener() {
		@Override
		public void propertyChange(PropertyChangeEvent evt) {
			notifyListenersOfValidityChanged();
		}
	};

	OptionsPanel() {
		super(new BorderLayout());
		// restricting use?
	}

	@Override
	public HelpLocation getHelpLocation() {
		if (optionsList != null) {
			for (VTOptions options : optionsList) {
				if (options != null) {
					HelpLocation helpLocation = options.getOptionsHelpLocation();
					if (helpLocation != null) {
						return helpLocation;
					}
				}
			}
		}

		// default
		return new HelpLocation("VersionTrackingPlugin", "Options_Panel");
	}

	@Override
	public Dimension getPreferredSize() {
		Dimension preferredSize = super.getPreferredSize();
		if (preferredSize.width < DEFAULT_PREFERRED_SIZE.width) {
			return DEFAULT_PREFERRED_SIZE;
		}
		return preferredSize;
	}

	@Override
	public void dispose() {
		if (optionsEditorPanelList != null) {
			removeAll();
			optionsEditorPanelList = null;
			optionsList = null;
		}
	}

	@Override
	public void enterPanel(WizardState<VTWizardStateKey> state) {
		dispose();
		List<VTProgramCorrelatorFactory> correlatorFactoryList = getCorrelators(state);

		optionsList = getCorrelatorOptions(state);
		if (optionsList == null) {
			optionsList = generateDefaultOptions(state);
		}

		JPanel panel = new JPanel(new VerticalLayout(30));

		optionsEditorPanelList = new ArrayList<OptionsEditorPanel>();
		for (int i = 0; i < correlatorFactoryList.size(); i++) {
			String correlatorName = correlatorFactoryList.get(i).getName();
			String title = correlatorName + " Options";
			if (optionsList.get(i) == null) {
				continue;
			}

			EditorStateFactory editorStateFactory = new EditorStateFactory();
			Options options = optionsList.get(i);
			List<String> optionNames = options.getLeafOptionNames();
			if (optionNames.isEmpty()) {
				continue;
			}

			OptionsEditorPanel optionsPanel =
				new OptionsEditorPanel(title, options, optionNames, editorStateFactory);
			optionsPanel.setOptionsPropertyChangeListener(propertyChangeListener);
			optionsEditorPanelList.add(optionsPanel);
			panel.add(optionsPanel);
		}
		JPanel outerPanel = new JPanel(new MiddleLayout());
		outerPanel.add(panel);
		JScrollPane scrollPane = new JScrollPane(outerPanel);
		scrollPane.getVerticalScrollBar().setUnitIncrement(5);
		add(scrollPane);
	}

	private List<VTOptions> generateDefaultOptions(WizardState<VTWizardStateKey> state) {
		List<VTOptions> list = new ArrayList<VTOptions>();
		List<VTProgramCorrelatorFactory> correlatorFactoryList = getCorrelators(state);
		for (VTProgramCorrelatorFactory vtProgramCorrelatorFactory : correlatorFactoryList) {
			list.add(vtProgramCorrelatorFactory.createDefaultOptions());
		}
		return list;
	}

	private List<VTOptions> getCorrelatorOptions(WizardState<VTWizardStateKey> state) {
		List<?> list = (List<?>) state.get(VTWizardStateKey.PROGRAM_CORRELATOR_OPTIONS_LIST);
		if (list == null) {
			return null;
		}
		return CollectionUtils.asList(list, VTOptions.class);
	}

	private List<VTProgramCorrelatorFactory> getCorrelators(WizardState<VTWizardStateKey> state) {
		List<?> list = (List<?>) state.get(VTWizardStateKey.PROGRAM_CORRELATOR_FACTORY_LIST);
		if (list == null) {
			return null;
		}
		return CollectionUtils.asList(list, VTProgramCorrelatorFactory.class);
	}

	@Override
	public WizardPanelDisplayability getPanelDisplayabilityAndUpdateState(
			WizardState<VTWizardStateKey> state) {

		List<VTOptions> tmpOptions = getCorrelatorOptions(state);
		if (tmpOptions == null) {
			tmpOptions = generateDefaultOptions(state);
		}
		for (VTOptions vtOptions : tmpOptions) {
			if (vtOptions == null) {
				continue;
			}

			List<String> names = vtOptions.getOptionNames();
			if (names.isEmpty()) {
				continue;
			}

			return WizardPanelDisplayability.MUST_BE_DISPLAYED;
		}
		return WizardPanelDisplayability.DO_NOT_DISPLAY;
	}

	@Override
	public void leavePanel(WizardState<VTWizardStateKey> state) {
		updateStateObjectWithPanelInfo(state);
	}

	@Override
	public void updateStateObjectWithPanelInfo(WizardState<VTWizardStateKey> state) {
		if (optionsList != null) {
			applyOptions();
		}

		List<VTOptions> newOptions =
			optionsList != null ? optionsList : generateDefaultOptions(state);

		state.put(VTWizardStateKey.PROGRAM_CORRELATOR_OPTIONS_LIST, newOptions);
	}

	@Override
	public String getTitle() {
		return "Correlator Options";
	}

	@Override
	public void initialize() {
		// nothing to do
	}

	@Override
	public boolean isValidInformation() {
		applyOptions();
		for (VTOptions options : optionsList) {
			if (options != null) {
				if (!options.validate()) {
					return false;
				}
			}

		}
		return true;
	}

	private void applyOptions() {
		try {
			for (OptionsEditorPanel panel : optionsEditorPanelList) {
				panel.apply();
			}
		}
		catch (InvalidInputException e) {
			Msg.showError(this, this, "Error", "could not apply options settings", e);
		}
	}

	@Override
	public void addDependencies(WizardState<VTWizardStateKey> state) {
		state.addDependency(VTWizardStateKey.PROGRAM_CORRELATOR_OPTIONS_LIST,
			VTWizardStateKey.PROGRAM_CORRELATOR_FACTORY_LIST);

	}

}
