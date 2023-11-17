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
package ghidra.features.bsim.gui.search.results;

import java.awt.BorderLayout;
import java.awt.Font;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.*;

import docking.DialogComponentProvider;
import ghidra.features.bsim.gui.BSimSearchPlugin;
import ghidra.features.bsim.gui.search.dialog.BSimFilterSet;
import ghidra.features.bsim.gui.search.dialog.BSimFilterSet.FilterEntry;
import ghidra.features.bsim.gui.search.dialog.BSimSearchSettings;
import ghidra.features.bsim.query.BSimServerInfo;
import ghidra.util.HelpLocation;
import ghidra.util.layout.PairLayout;

/**
 * Dialog for displaying the search criteria used to generate a BSim Similar Functions Search.
 */
public class BSimSearchInfoDisplayDialog extends DialogComponentProvider {

	private BSimServerInfo server;
	private BSimSearchSettings settings;
	private boolean isOverview;

	public BSimSearchInfoDisplayDialog(BSimServerInfo server, BSimSearchSettings searchSettings,
			boolean isOverview) {
		super("BSim Search Criteria");
		this.server = server;
		this.settings = searchSettings;
		this.isOverview = isOverview;
		addWorkPanel(buildWorkPanel());
		String anchor = isOverview ? "Overview_Search_Info_Action" : "Search_Info_Action";
		setHelpLocation(new HelpLocation(BSimSearchPlugin.HELP_TOPIC, anchor));
		setRememberSize(false);
		addOKButton();
	}

	private JComponent buildWorkPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.add(buildSearchInfoPanel(), BorderLayout.NORTH);
		return panel;
	}

	private JPanel buildSearchInfoPanel() {
		JPanel panel = new JPanel(new PairLayout(0, 10));
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		JLabel dataLabel = new JLabel("Search Options:");
		dataLabel.setFont(dataLabel.getFont().deriveFont(Font.ITALIC));
		panel.add(dataLabel);
		panel.add(new JLabel(""));

		panel.add(new JLabel("BSim Server:", SwingConstants.RIGHT));
		panel.add(getDisplayField(server.getDBName()));

		panel.add(new JLabel("Similarity Threshold:", SwingConstants.RIGHT));
		panel.add(getDisplayField(Double.toString(settings.getSimilarity())));

		panel.add(new JLabel("Confidence Threshold:", SwingConstants.RIGHT));
		panel.add(getDisplayField(Double.toString(settings.getConfidence())));

		if (!isOverview) {
			panel.add(new JLabel("Max Results:", SwingConstants.RIGHT));
			panel.add(getDisplayField(Integer.toString(settings.getMaxResults())));
			addFilters(panel);
		}
		return panel;
	}

	private void addFilters(JPanel panel) {
		panel.add(new JLabel(""));
		panel.add(new JLabel(""));
		JLabel filterLabel = new JLabel("Filters:");
		filterLabel.setFont(filterLabel.getFont().deriveFont(Font.ITALIC));
		panel.add(filterLabel);
		panel.add(new JLabel(""));

		BSimFilterSet bSimFilterSet = settings.getBSimFilterSet();
		List<FilterEntry> filters = bSimFilterSet.getFilterEntries();
		if (filters.isEmpty()) {
			panel.add(new JLabel("None", SwingConstants.RIGHT));
			return;
		}
		for (FilterEntry filter : filters) {
			panel.add(new JLabel(filter.filterType().getLabel() + ":", SwingConstants.RIGHT));
			panel.add(getDisplayField(getValueString(filter.values())));
		}
	}

	private JComponent getDisplayField(String data) {
		JTextField textField = new JTextField(data);
		textField.setEditable(false);
		return textField;
	}

	private String getValueString(List<String> values) {
		return values.stream().collect(Collectors.joining(",  "));
	}

	@Override
	protected void okCallback() {
		close();
	}
}
