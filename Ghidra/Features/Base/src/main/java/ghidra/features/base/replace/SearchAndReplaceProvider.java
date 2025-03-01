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
package ghidra.features.base.replace;

import java.awt.*;

import javax.swing.*;

import ghidra.app.util.HelpTopics;
import ghidra.features.base.quickfix.*;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

/**
 * Subclass of the {@link QuckFixTableProvider} that customizes it specifically for search and replace
 * operations.
 */
public class SearchAndReplaceProvider extends QuckFixTableProvider {

	private SearchAndReplacePlugin plugin;
	private SearchAndReplaceQuery query;

	public SearchAndReplaceProvider(SearchAndReplacePlugin plugin, Program program,
			SearchAndReplaceQuery query) {

		super(plugin.getTool(), "Search And Replace", plugin.getName(), program,
			new SearchAndReplaceQuckFixTableLoader(program, query));
		this.plugin = plugin;
		this.query = query;
		setTitle(generateTitle());
		setTabText(getTabTitle());
		addToTool();
		setHelpLocation(new HelpLocation(HelpTopics.SEARCH, "Search_And_Replace_Results"));
	}

	@Override
	protected void tableLoaded(boolean wasCancelled, TableDataLoader<QuickFix> loader) {
		if (!loader.didProduceData()) {
			Msg.showInfo(getClass(), getComponent(), "No Results Found!",
				"No results for \"" + query.getSearchText() + "\" found.");
			closeComponent();
			return;
		}
		setVisible(true);
		if (loader.maxDataSizeReached()) {
			Msg.showInfo(getClass(), getComponent(), "Search Limit Exceeded!",
				"Stopped search after finding " + query.getSearchLimit() + " matches.\n" +
					"The search limit can be changed at Edit->Tool Options, under Search.");
		}
		toFront();
	}

	@Override
	public void closeComponent() {
		super.closeComponent();
		plugin.providerClosed(this);
	}

	private String getTabTitle() {
		return "\"" + query.getSearchText() + "\" -> \"" +
			query.getReplacementText() + "\"";
	}

	private String generateTitle() {
		return "Search & Replace:  " + getTabTitle();
	}

	@Override
	protected JPanel buildMainPanel() {
		JPanel quickFixPanel = super.buildMainPanel();

		JPanel panel = new JPanel(new BorderLayout());
		panel.add(quickFixPanel, BorderLayout.CENTER);
		panel.add(buildButtonPanel(), BorderLayout.SOUTH);

		return panel;
	}

	private Component buildButtonPanel() {
		JButton replaceButton = new JButton("Replace All");
		JButton dismissButton = new JButton("Dismiss");
		replaceButton.addActionListener(e -> executeAll());
		dismissButton.addActionListener(e -> closeComponent());

		JPanel panel = new JPanel(new FlowLayout(FlowLayout.CENTER, 20, 0));
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		panel.add(replaceButton);
		panel.add(dismissButton);
		return panel;
	}

}
