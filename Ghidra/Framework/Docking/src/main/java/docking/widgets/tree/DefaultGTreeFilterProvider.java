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

import javax.accessibility.AccessibleContext;
import javax.swing.*;
import javax.swing.border.BevelBorder;

import org.jdom.Attribute;
import org.jdom.Element;

import docking.DockingWindowManager;
import docking.widgets.EmptyBorderButton;
import docking.widgets.filter.*;
import docking.widgets.label.GLabel;
import docking.widgets.tree.internal.DefaultGTreeDataTransformer;
import docking.widgets.tree.support.GTreeFilter;
import ghidra.framework.options.PreferenceState;
import ghidra.util.FilterTransformer;
import ghidra.util.HelpLocation;
import help.HelpService;

public class DefaultGTreeFilterProvider implements GTreeFilterProvider {
	private static final String FILTER_STATE = "FILTER_STATE";

	private FilterTextField filterField;
	private EmptyBorderButton filterStateButton;
	private GTreeFilterFactory filterFactory;
	private FilterDocumentListener filterListener = new FilterDocumentListener();

	// This tracks whether the filter has been configured to be part of the display, whether by the
	// user or via the API.
	private boolean isFilterDisplayed = true;

	private GTree gTree;
	private JPanel filterPanel;
	private FilterTransformer<GTreeNode> dataTransformer = new DefaultGTreeDataTransformer();

	private boolean optionsSet;

	public DefaultGTreeFilterProvider(GTree gTree) {
		this.gTree = gTree;
		filterFactory = new GTreeFilterFactory(new FilterOptions());
		filterPanel = createFilterPanel();
	}

	@Override
	public GTreeFilterProvider copy(GTree newTree) {
		DefaultGTreeFilterProvider newProvider = new DefaultGTreeFilterProvider(newTree);

		FilterOptions existingOptions = filterFactory.getFilterOptions();
		newProvider.setFilterOptions(existingOptions);

		String existingText = filterField.getText();
		newProvider.setFilterText(existingText);

		if (!filterField.isEnabled()) {
			newProvider.setEnabled(false);
		}

		String accessibleNamePrefix = filterField.getAccessibleNamePrefix();
		if (accessibleNamePrefix != null) {
			newProvider.setAccessibleNamePrefix(accessibleNamePrefix);
		}

		return newProvider;
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

	@Override
	public void setAccessibleNamePrefix(String namePrefix) {
		filterField.setAccessibleNamePrefix(namePrefix);

		String buttonNamePrefix = namePrefix + " Filter Options";
		filterStateButton.setName(buttonNamePrefix + " Button");
		AccessibleContext context = filterStateButton.getAccessibleContext();

		// Don't add "Button" to prefix because screen readers reads the name followed by the role,
		// which in this case, is "button"
		context.setAccessibleName(buttonNamePrefix);

		// Setting the accessible description to empty string prevents it from reading any tooltips
		// on the button when the button gets focus. These buttons tend to have particularly large
		// tooltips which seem excessive to read to the user every time they get focus. We may need
		// to revisit this decision.
		context.setAccessibleDescription("");
	}

	private void updateModelFilter() {

		FilterOptions filterOptions = filterFactory.getFilterOptions();
		filterStateButton.setIcon(filterOptions.getFilterStateIcon());
		filterStateButton.setToolTipText(filterOptions.getFilterDescription());

		gTree.filterChanged();
	}

	private PreferenceState createPreferenceState() {

		if (isDefaultFilterOptions()) {
			return null; // don't save default settings
		}

		if (optionsSet) {
			return null; // don't save custom options (see setPreferredOptions())
		}

		PreferenceState preferenceState = new PreferenceState();
		Element element = filterFactory.getFilterOptions().toXML();
		element.setAttribute("IS_SHOWING", Boolean.toString(isFilterDisplayed));
		preferenceState.putXmlElement(FILTER_STATE, element);
		return preferenceState;
	}

	private boolean isDefaultFilterOptions() {
		return isFilterDisplayed && filterFactory.isDefault();
	}

	public FilterOptions getFilterOptions() {
		return filterFactory.getFilterOptions();
	}

	/**
	 * A method to allow clients to change the current filter settings to something they would like
	 * for their particular use case.  This differs from {@link #setFilterOptions(FilterOptions)} in
	 * that this method will also disable saving any changes the user makes to the filter.  If you
	 * do not need to disable preference saving, then call the other method.
	 * <p>
	 * This method disables preference saving with the assumption that some clients always wish the
	 * filter to start in the same preferred state instead of where the user last left it.
	 * It is not clear  why we do that, but it is probably based on the assumption that the API 
	 * client wants the filter to always start in the preferred state.  The prevents filter from 
	 * being restored with a previous user filter that does not make sense for the general case.
	 * 
	 * @param filterOptions the options
	 * @see #setFilterOptions(FilterOptions)
	 */
	public void setPreferredFilterOptions(FilterOptions filterOptions) {
		optionsSet = true;
		filterFactory = new GTreeFilterFactory(filterOptions);
		updateModelFilter();
	}

	/**
	 * Sets the options for this filter provider.
	 * @param filterOptions the new filter options
	 */
	public void setFilterOptions(FilterOptions filterOptions) {
		filterFactory = new GTreeFilterFactory(filterOptions);
		updateModelFilter();
	}

	@Override
	public void activate() {
		if (!isFilterDisplayed) {
			filterPanel.setVisible(true);
			isFilterDisplayed = true;
		}

		filterPanel.requestFocus();
	}

	@Override
	public void toggleVisibility() {
		doToggleVisibility();
		if (isFilterDisplayed) {
			filterPanel.requestFocus();
		}
	}

	private void doToggleVisibility() {
		if (isFilterDisplayed) {
			setFilterText(""); // clear the filter when not showing to avoid confusing the user
			filterPanel.setVisible(false);
			isFilterDisplayed = false;
			return;
		}

		// make filter displayed and maybe focus it
		filterPanel.setVisible(true);
		isFilterDisplayed = true;
	}

	@Override
	public void loadFilterPreference(DockingWindowManager windowManager) {

		if (windowManager == null) {
			return;
		}

		// Check to see if the options were specifically set via the API.  In this case, we do not
		// save user changes to the filter options.  Not sure exactly why at this point, or if this
		// is even the preferred behavior.  Leaving it this way for now.
		if (optionsSet) {
			return;
		}

		// 
		// We have just been loaded into the UI.  The window manager has the current preference 
		// state if any has been saved.  First, load any saved state into this class.
		// 
		String key = gTree.getPreferenceKey();
		PreferenceState preferenceState = windowManager.getPreferenceState(key);
		loadFromPreferenceState(preferenceState);

		//
		// Next, register a preference state supplier so that we will get asked for our current 
		// state when the tool is saved.  When asked for our state, we will make the decision as to
		// whether or not we have anything to save.  There is no need to remove our supplier later, 
		// as it will be disposed when the tool is closed.
		// 
		windowManager.registerPreferenceStateSupplier(key, () -> createPreferenceState());
	}

	private void loadFromPreferenceState(PreferenceState preferenceState) {
		if (preferenceState == null) {
			return;
		}

		Element element = preferenceState.getXmlElement(FILTER_STATE);
		if (element == null) {
			return;
		}

		FilterOptions filterOptions = FilterOptions.restoreFromXML(element);
		filterFactory = new GTreeFilterFactory(filterOptions);

		Attribute attribute = element.getAttribute("IS_SHOWING");
		if (attribute != null) { // null when loading old settings
			boolean shouldBeDisplayed = Boolean.parseBoolean(attribute.getValue());
			if (shouldBeDisplayed != isFilterDisplayed) {
				doToggleVisibility();
			}
		}

		updateModelFilter();
	}

	private JPanel createFilterPanel() {
		JPanel newFilterPanel = new JPanel(new BorderLayout()) {
			@Override
			public void requestFocus() {
				filterField.requestFocus();
			}
		};
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

	@Override
	public void dispose() {
		DockingWindowManager dwm = DockingWindowManager.getInstance(getFilterComponent());
		if (dwm != null) {
			String key = gTree.getPreferenceKey();
			dwm.removePreferenceStateSupplier(key);
		}
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

}
