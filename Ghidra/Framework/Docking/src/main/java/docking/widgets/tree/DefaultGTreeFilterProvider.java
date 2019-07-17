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
package docking.widgets.tree;

import java.awt.BorderLayout;

import javax.swing.*;
import javax.swing.border.BevelBorder;

import org.jdom.Element;

import docking.DockingWindowManager;
import docking.help.HelpService;
import docking.widgets.EmptyBorderButton;
import docking.widgets.filter.*;
import docking.widgets.label.GLabel;
import docking.widgets.tree.internal.DefaultGTreeDataTransformer;
import docking.widgets.tree.support.GTreeFilter;
import ghidra.framework.options.PreferenceState;
import ghidra.util.FilterTransformer;
import ghidra.util.HelpLocation;

public class DefaultGTreeFilterProvider implements GTreeFilterProvider {
	private static final String FILTER_STATE = "FILTER_STATE";

	private FilterTextField filterField;
	private EmptyBorderButton filterStateButton;
	private GTreeFilterFactory filterFactory;
	private FilterDocumentListener filterListener = new FilterDocumentListener();

	private GTree gTree;
	private JPanel filterPanel;
	private FilterTransformer<GTreeNode> dataTransformer = new DefaultGTreeDataTransformer();

	private String preferenceKey;
	private boolean optionsSet;

	public DefaultGTreeFilterProvider(GTree gTree) {
		this.gTree = gTree;
		filterFactory = new GTreeFilterFactory(new FilterOptions());
		filterPanel = createFilterPanel();
	}

	@Override
	public JComponent getFilterComponent() {
		return filterPanel;
	}

	@Override
	public void setFilterText(String text) {
		filterListener.enableEvents(false);
		filterField.setText(text);
		updateModelFilter();
		filterListener.enableEvents(true);
	}

	@Override
	public void setEnabled(boolean enabled) {
		filterField.setEnabled(enabled);
	}

	private void updateModelFilter() {
		gTree.filterChanged();
	}

	private void saveFilterState() {
		PreferenceState preferenceState = new PreferenceState();
		preferenceState.putXmlElement(FILTER_STATE, filterFactory.getFilterOptions().toXML());

		DockingWindowManager dwm = DockingWindowManager.getInstance(gTree.getJTree());
		if (dwm != null) {
			dwm.putPreferenceState(preferenceKey, preferenceState);
		}
	}

	public void setFilterOptions(FilterOptions filterOptions) {
		optionsSet = true;
		filterFactory = new GTreeFilterFactory(filterOptions);
		saveFilterState();
		updateModelFilter();
	}

	@Override
	public void loadFilterPreference(DockingWindowManager windowManager,
			String uniquePreferenceKey) {
		preferenceKey = uniquePreferenceKey;
		if (optionsSet) {  // if the options were specifically set, don't restore saved values
			return;
		}

		if (windowManager == null) {
			return;
		}

		PreferenceState preferenceState = windowManager.getPreferenceState(preferenceKey);
		if (preferenceState == null) {
			return;
		}

		Element xmlElement = preferenceState.getXmlElement(FILTER_STATE);
		if (xmlElement != null) {
			FilterOptions filterOptions = FilterOptions.restoreFromXML(xmlElement);
			filterFactory = new GTreeFilterFactory(filterOptions);
		}
		updateModelFilter();
	}

	private JPanel createFilterPanel() {
		JPanel newFilterPanel = new JPanel(new BorderLayout());
		newFilterPanel.setBorder(BorderFactory.createBevelBorder(BevelBorder.LOWERED));
		JLabel filterLabel = new GLabel(" Filter: ");
		newFilterPanel.add(filterLabel, BorderLayout.WEST);

		filterField = new FilterTextField(gTree.getJTree());
		newFilterPanel.add(filterField, BorderLayout.CENTER);
		filterField.addFilterListener(filterListener);

		filterStateButton = new EmptyBorderButton(filterFactory.getFilterStateIcon());
		filterStateButton.addActionListener(e -> {
			FilterOptionsEditorDialog dialog =
				new FilterOptionsEditorDialog(filterFactory.getFilterOptions());
			DockingWindowManager.showDialog(filterPanel, dialog);
			FilterOptions newFilterOptions = dialog.getResultFilterOptions();
			if (newFilterOptions != null) {
				filterFactory = new GTreeFilterFactory(newFilterOptions);

				filterStateButton.setIcon(newFilterOptions.getFilterStateIcon());
				filterStateButton.setToolTipText(newFilterOptions.getFilterDescription());

				saveFilterState();
				updateModelFilter();
			}
		});

		HelpService helpService = DockingWindowManager.getHelpService();
		HelpLocation helpLocation = new HelpLocation("Trees", "Filters");
		helpService.registerHelp(filterStateButton, helpLocation);
		helpService.registerHelp(filterLabel, helpLocation);
		helpService.registerHelp(filterField, helpLocation);

		filterStateButton.setToolTipText("Filter Options");
		newFilterPanel.add(filterStateButton, BorderLayout.EAST);
		return newFilterPanel;
	}

	private class FilterDocumentListener implements FilterListener {
		private boolean processEvents = true;

		@Override
		public void filterChanged(String text) {
			if (processEvents) {
				updateModelFilter();
			}
		}

		void enableEvents(boolean enable) {
			processEvents = enable;
		}
	}

	@Override
	public GTreeFilter getFilter() {
		return filterFactory.getTreeFilter(filterField.getText(), dataTransformer);
	}

	@Override
	public String getFilterText() {
		return filterField.getText();
	}

	@Override
	public void setDataTransformer(FilterTransformer<GTreeNode> transformer) {
		this.dataTransformer = transformer;
	}

}
