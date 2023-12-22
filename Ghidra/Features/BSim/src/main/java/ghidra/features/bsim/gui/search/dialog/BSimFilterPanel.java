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
package ghidra.features.bsim.gui.search.dialog;

import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import javax.swing.*;

import docking.widgets.EmptyBorderButton;
import generic.theme.GThemeDefaults.Colors.Viewport;
import ghidra.features.bsim.gui.filters.BSimFilterType;
import ghidra.features.bsim.gui.search.dialog.BSimFilterSet.FilterEntry;
import ghidra.util.layout.VerticalLayout;
import resources.Icons;
import utility.function.Callback;

/**
 * Panel for specifying and managing BSim filters.
 */
public class BSimFilterPanel extends JPanel {

	private JPanel mainPanel;
	private List<BSimFilterType> filters;
	private List<FilterWidget> filterWidgets = new ArrayList<>();
	private Consumer<FilterWidget> removeMeConsumer = this::removeFilterWidget;
	private Callback changeListener;

	/**
	 * Constructs a filer panel with no filters
	 * @param changeListener the callback when filters change
	 */
	public BSimFilterPanel(Callback changeListener) {
		this(List.of(BSimFilterType.BLANK), new BSimFilterSet(), changeListener);
	}

	/**
	 * Constructs a filer panel with existing filters
	 * @param filters the list of filterTypes to display in the comboBox
	 * @param filterSet the current filter settings
	 * @param changeListener the callback when filters change
	 */
	public BSimFilterPanel(List<BSimFilterType> filters, BSimFilterSet filterSet,
			Callback changeListener) {
		super(new BorderLayout());
		this.changeListener = changeListener;
		mainPanel = new ScrollablePanel();
		JScrollPane scroll = new JScrollPane(mainPanel);
		scroll.getViewport().setBackground(Viewport.UNEDITABLE_BACKGROUND);
		add(scroll, BorderLayout.CENTER);
		add(buildButtonPanel(), BorderLayout.EAST);
		this.filters = filters;
		setFilterSet(filterSet);
	}

	/**
	 * Sets the panel to have the given filters
	 * @param filterSet the set of filters to show in the panel
	 */
	public void setFilterSet(BSimFilterSet filterSet) {
		filterWidgets.removeAll(filterWidgets);
		mainPanel.removeAll();
		List<FilterEntry> filterEntries = filterSet.getFilterEntries();

		for (FilterEntry filterEntry : filterEntries) {
			FilterWidget widget = new FilterWidget(filters, removeMeConsumer, changeListener);
			widget.setFilter(filterEntry.filterType(), filterEntry.values());
			addFilterWidget(widget);
		}
		if (filterWidgets.isEmpty()) {
			addFilterWidget();
		}
	}

	/**
	 * Sets the choices for filter types in the filter comboBoxes.
	 * @param filters the filter types the user can choose
	 */
	public void setFilters(List<BSimFilterType> filters) {
		if (filters == null || filters.isEmpty()) {
			filters = List.of(BSimFilterType.BLANK);
		}
		this.filters = filters;
		for (FilterWidget widget : filterWidgets) {
			widget.setFilters(this.filters);
		}
	}

	/**
	 * Returns the set of valid filters that are displayed in this filter panel
	 * @return the set of valid filters that are displayed in this filter panel
	 */
	public BSimFilterSet getFilterSet() {
		BSimFilterSet set = new BSimFilterSet();
		for (FilterWidget filter : filterWidgets) {
			if (!filter.isBlank() && filter.hasValidValue()) {
				set.addEntry(filter.getSelectedFilter(), filter.getValues());
			}
		}
		return set;
	}

	/**
	 * Returns true the panel has only valid filters. (Blank filter is ok)
	 * @return true the panel has only valid filters
	 */
	public boolean hasValidFilters() {
		for (FilterWidget filter : filterWidgets) {
			if (!filter.isBlank() && !filter.hasValidValue()) {
				return false;
			}
		}
		return true;
	}

	private Component buildButtonPanel() {
		JPanel panel = new JPanel(new VerticalLayout(10));
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 0, 0));
		JButton addFilterButton = new EmptyBorderButton(Icons.ADD_ICON);
		addFilterButton.setToolTipText("Add filter");
		addFilterButton.setName("Add Filter");
		addFilterButton.addActionListener(e -> addFilterWidget());
		panel.add(addFilterButton);
		return panel;
	}

	private void addFilterWidget() {
		addFilterWidget(new FilterWidget(filters, removeMeConsumer, changeListener));
		validate();
	}

	private void addFilterWidget(FilterWidget widget) {
		filterWidgets.add(widget);
		mainPanel.add(widget);
	}

	private void removeFilterWidget(FilterWidget widget) {
		filterWidgets.remove(widget);
		mainPanel.remove(widget);
		if (mainPanel.getComponentCount() == 0) {
			addFilterWidget();
		}
		changeListener.call();
		validate();

	}

//==================================================================================================
// Test methods
//==================================================================================================
	List<FilterWidget> getFilterWidgets() {
		return filterWidgets;
	}

//==================================================================================================
// Inner classes
//==================================================================================================
	private class ScrollablePanel extends JPanel implements Scrollable {
		public ScrollablePanel() {
			super(new VerticalLayout(5));
			setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		}

		@Override
		public Dimension getPreferredScrollableViewportSize() {
			Dimension preferredSize = getPreferredSize();
			preferredSize.height = 100;
			return preferredSize;
		}

		@Override
		public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation,
				int direction) {
			return 10;
		}

		@Override
		public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation,
				int direction) {
			return 20;
		}

		@Override
		public boolean getScrollableTracksViewportWidth() {
			return true;
		}

		@Override
		public boolean getScrollableTracksViewportHeight() {
			return false;
		}

	}

}
