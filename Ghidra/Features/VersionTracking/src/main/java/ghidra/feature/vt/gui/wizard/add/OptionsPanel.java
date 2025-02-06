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
package ghidra.feature.vt.gui.wizard.add;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.util.*;

import javax.swing.*;

import docking.options.editor.OptionsEditorPanel;
import ghidra.feature.vt.api.main.VTProgramCorrelatorFactory;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.framework.options.EditorStateFactory;
import ghidra.util.layout.VerticalLayout;
import utility.function.Callback;

/**
 * Panel for displaying version tracking correlator options for selected correlators. Used by
 * the {@link OptionsStep} of the "add to version tracking session" wizard to configure the
 * selected correlators from a previous step.
 */
public class OptionsPanel extends JPanel {

	private static final Dimension DEFAULT_PREFERRED_SIZE = new Dimension(650, 350);

	private List<OptionsEditorPanel> optionsEditorPanelList = new ArrayList<>();
	private Callback statusChangedCallback;
	private Map<VTProgramCorrelatorFactory, VTOptions> optionsMap = new HashMap<>();

	private JPanel stagingPanel;

	OptionsPanel(Callback statusChangedCallback) {
		super(new BorderLayout());
		this.statusChangedCallback = statusChangedCallback;

		stagingPanel = new JPanel(new BorderLayout());
		stagingPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
		JScrollPane scrollPane = new JScrollPane(stagingPanel);
		scrollPane.getVerticalScrollBar().setUnitIncrement(5);
		add(scrollPane);
	}

	@Override
	public Dimension getPreferredSize() {
		Dimension preferredSize = super.getPreferredSize();
		if (preferredSize.width < DEFAULT_PREFERRED_SIZE.width) {
			return DEFAULT_PREFERRED_SIZE;
		}
		return preferredSize;
	}

	public boolean isApplicable(List<VTProgramCorrelatorFactory> correlators) {
		updateOptionsMap(correlators);
		return !optionsMap.isEmpty();
	}

	private void updateOptionsMap(List<VTProgramCorrelatorFactory> correlators) {
		optionsMap.keySet().retainAll(correlators);
		for (VTProgramCorrelatorFactory correlator : correlators) {
			if (!optionsMap.containsKey(correlator)) {
				VTOptions defaultOptions = correlator.createDefaultOptions();
				if (defaultOptions != null) {
					optionsMap.put(correlator, defaultOptions);
				}
			}
		}
	}

	void initialize(List<VTProgramCorrelatorFactory> correlators) {
		updateOptionsMap(correlators);
		JPanel panel = new JPanel(new VerticalLayout(30));
		optionsEditorPanelList.clear();
		for (VTProgramCorrelatorFactory correlator : correlators) {
			OptionsEditorPanel optionsPanel = buildOptionsPanel(correlator);
			if (optionsPanel != null) {
				optionsEditorPanelList.add(optionsPanel);
				optionsPanel.setOptionsPropertyChangeListener(e -> statusChangedCallback.call());
				panel.add(optionsPanel);
			}
		}

		stagingPanel.removeAll();
		stagingPanel.add(panel, BorderLayout.CENTER);
		stagingPanel.revalidate();
	}

	private OptionsEditorPanel buildOptionsPanel(VTProgramCorrelatorFactory factory) {
		VTOptions options = optionsMap.get(factory);
		if (options == null) {
			return null;
		}

		String title = factory.getName() + " Options";

		EditorStateFactory editorStateFactory = new EditorStateFactory();
		List<String> optionNames = options.getLeafOptionNames();
		if (optionNames.isEmpty()) {
			return null;
		}
		Collections.sort(optionNames);
		return new OptionsEditorPanel(title, options, optionNames, editorStateFactory);
	}

	public boolean hasValidOptions() {
		applyOptions();
		for (VTOptions options : optionsMap.values()) {
			if (options != null) {
				if (!options.validate()) {
					return false;
				}
			}

		}
		return true;
	}

	private void applyOptions() {
		for (OptionsEditorPanel panel : optionsEditorPanelList) {
			panel.apply();
		}
	}

	Map<VTProgramCorrelatorFactory, VTOptions> getOptionsMap() {
		return optionsMap;
	}

}
