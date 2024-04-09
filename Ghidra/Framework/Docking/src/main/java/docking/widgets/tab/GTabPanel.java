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
package docking.widgets.tab;

import java.awt.Container;
import java.awt.event.*;
import java.util.*;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.swing.*;

import ghidra.util.layout.HorizontalLayout;
import utility.function.Dummy;

/**
 * Component for displaying a list of items as a series of horizontal tabs where exactly one tab
 * is selected. 
 * <P>
 * If there are too many tabs to display horizontally, a "hidden tabs" control will be
 * displayed that when activated, will display a popup dialog with a scrollable list of all 
 * possible values.
 * <P>
 * It also supports the idea of a highlighted tab which represents a value that is not selected,
 * but is a candidate to be selected. For example, when the tab panel has focus, using the left
 * and right arrows will highlight different tabs. Then pressing enter will cause the highlighted
 * tab to be selected. 
 * <P>
 * The clients of this component can also supply functions for customizing the name, icon, and 
 * tooltip for values. They can also add consumers for when the selected value changes or a value
 * is removed from the tab panel. Clients can also install a predicate for the close tab action so
 * they can process it before the value is removed and possibly veto the remove.
 *
 * @param <T> The type of values in the tab panel.
 */
public class GTabPanel<T> extends JPanel {

	private T selectedValue;
	private T highlightedValue;
	private boolean ignoreFocusLost;
	private TabListPopup<T> tabList;
	private String tabTypeName;

	private Set<T> allValues = new LinkedHashSet<>();
	private List<GTab<T>> allTabs = new ArrayList<>();
	private HiddenValuesButton hiddenValuesControl = new HiddenValuesButton(this);
	private Function<T, String> nameFunction = v -> v.toString();
	private Function<T, Icon> iconFunction = Dummy.function();
	private Function<T, String> toolTipFunction = Dummy.function();
	private Consumer<T> selectedTabConsumer = Dummy.consumer();
	private Consumer<T> closeTabConsumer = t -> removeTab(t);
	private boolean showTabsAlways = true;

	/**
	 * Constructor
	 * @param tabTypeName the name of the type of values in the tab panel. This will be used to 
	 * set accessible descriptions.
	 */
	public GTabPanel(String tabTypeName) {
		this.tabTypeName = tabTypeName;
		setLayout(new HorizontalLayout(0));
		setFocusable(true);
		getAccessibleContext().setAccessibleDescription(
			"Use left and right arrows to highlight other tabs and press enter to select " +
				"the highlighted tab");

		addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				closeTabList();
				rebuildTabs();
			}
		});

		addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				int keyCode = e.getKeyCode();
				switch (keyCode) {
					case KeyEvent.VK_SPACE:
					case KeyEvent.VK_ENTER:
						selectHighlightedValue();
						e.consume();
						break;
					case KeyEvent.VK_LEFT:
						highlightNextPreviousTab(false);
						e.consume();
						break;
					case KeyEvent.VK_RIGHT:
						highlightNextPreviousTab(true);
						e.consume();
						break;
				}
			}

		});
		addFocusListener(new FocusListener() {
			@Override
			public void focusGained(FocusEvent e) {
				updateTabColors();
			}

			@Override
			public void focusLost(FocusEvent e) {
				highlightedValue = null;
				updateAccessibleName();
				updateTabColors();
			}
		});
	}

	/**
	 * Add a new tab to the panel for the given value.
	 * @param value the value for the new tab
	 */
	public void addTab(T value) {
		doAddValue(value);
		rebuildTabs();
	}

	/**
	 * Add tabs for each value in the given list.
	 * @param values the values to add tabs for
	 */
	public void addTabs(List<T> values) {
		for (T t : values) {
			doAddValue(t);
		}
		rebuildTabs();
	}

	/**
	 * Removes the tab with the given value.
	 * @param value the value for which to remove its tab
	 */
	public void removeTab(T value) {
		allValues.remove(value);
		highlightedValue = null;
		// ensure there is a valid selected value
		if (value == selectedValue) {
			selectTab(null);
		}
		else {
			rebuildTabs();
		}
	}

	/**
	 * Remove tabs for all values in the given list.
	 * @param values the values to remove from the tab panel
	 */
	public void removeTabs(Collection<T> values) {
		allValues.removeAll(values);

		if (!allValues.contains(selectedValue)) {
			selectTab(null);
		}
		else {
			rebuildTabs();
		}
	}

	/**
	 * Returns the currently selected tab. If the panel is not empty, there will always be a
	 * selected tab.
	 * @return the currently selected tab or null if the panel is empty
	 */
	public T getSelectedTabValue() {
		return selectedValue;
	}

	/**
	 * Returns the currently highlighted tab if a tab is highlighted. Note: the selected tab can
	 * never be highlighted.
	 * @return the currently highlighted tab or null if no tab is highligted
	 */
	public T getHighlightedTabValue() {
		return highlightedValue;
	}

	/**
	 * Makes the tab for the given value be the selected tab.
	 * @param value the value whose tab is to be selected
	 */
	public void selectTab(T value) {
		if (value != null && !allValues.contains(value)) {
			throw new IllegalArgumentException(
				"Attempted to set selected value to non added value");
		}
		closeTabList();
		highlightedValue = null;
		selectedValue = value;
		rebuildTabs();
		selectedTabConsumer.accept(value);
	}

	/**
	 * Returns a list of values for all the tabs in the panel.
	 * @return  a list of values for all the tabs in the panel
	 */
	public List<T> getTabValues() {
		return new ArrayList<>(allValues);
	}

	/**
	 * Returns true if the tab for the given value is visible on the tab panel.
	 * @param value the value to test if visible
	 * @return true if the tab for the given value is visible on the tab panel
	 */
	public boolean isVisibleTab(T value) {
		for (GTab<T> gTab : allTabs) {
			if (gTab.getValue().equals(value)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Returns the total number of tabs both visible and hidden.
	 * @return the total number of tabs both visible and hidden.
	 */
	public int getTabCount() {
		return allValues.size();
	}

	/**
	 * Sets the tab for the given value to be highlighted. If the value is selected, then the
	 * highlighted tab will be set to null.
	 * @param value the value to highlight its tab
	 */
	public void highlightTab(T value) {
		highlightedValue = value == selectedValue ? null : value;
		updateTabColors();
		updateAccessibleName();
	}

	/**
	 * Returns true if not all tabs are visible in the tab panel.
	 * @return true if not all tabs are visible in the tab panel
	 */
	public boolean hasHiddenTabs() {
		return allTabs.size() < allValues.size();
	}

	/**
	 * Returns a list of all tab values that are not visible.
	 * @return a list of all tab values that are not visible
	 */
	public List<T> getHiddenTabs() {
		Set<T> hiddenValues = new LinkedHashSet<T>(allValues);
		hiddenValues.removeAll(getVisibleTabs());
		return new ArrayList<>(hiddenValues);
	}

	/**
	 * Returns a list of all tab values that are visible.
	 * @return a list of all tab values that are visible
	 */
	public List<T> getVisibleTabs() {
		return allTabs.stream().map(t -> t.getValue()).collect(Collectors.toList());
	}

	/**
	 * Shows a popup dialog window with a filterable and scrollable list of all tab values.
	 * @param show true to show the popup list, false to close the popup list
	 */
	public void showTabList(boolean show) {
		if (show) {
			showTabList();
		}
		else {
			closeTabList();
		}
	}

	/**
	 * Moves the highlight to the next or previous tab from the current highlight. If there is no
	 * current highlight, it will highlight the next or previous tab from the selected tab.
	 * @param forward true moves the highlight to the right; otherwise move the highlight to the
	 * left
	 */
	public void highlightNextPreviousTab(boolean forward) {
		if (allValues.size() < 2) {
			return;
		}
		T current = highlightedValue == null ? selectedValue : highlightedValue;
		if (isShowingTabList()) {
			current = null;
			closeTabList();
		}
		T next = forward ? getTabbedValueAfter(current) : getTabbedValueBefore(current);
		highlightTab(next);
		if (next == null) {
			showTabList(true);
		}
	}

	/**
	 * Informs the tab panel that some displayable property about the value has changed and the
	 * tabs label, icon, and tooltip need to be updated.
	 * @param value the value that has changed
	 */
	public void refreshTab(T value) {
		int tabIndex = getTabIndex(value);
		if (tabIndex >= 0) {
			allTabs.get(tabIndex).refresh();
		}
	}

	/**
	 * Sets a function to be used to generated a display name for a given value. The display name
	 * is used in the tab, the filter, and the accessible description.
	 * @param nameFunction the function to generate display names for values
	 */
	public void setNameFunction(Function<T, String> nameFunction) {
		this.nameFunction = nameFunction;
	}

	/**
	 * Sets a function to be used to generated an icon for a given value. 
	 * @param iconFunction the function to generate icons for values
	 */
	public void setIconFunction(Function<T, Icon> iconFunction) {
		this.iconFunction = iconFunction;
	}

	/**
	 * Sets a function to be used to generated an tooltip for a given value. 
	 * @param toolTipFunction the function to generate tooltips for values
	 */
	public void setToolTipFunction(Function<T, String> toolTipFunction) {
		this.toolTipFunction = toolTipFunction;
	}

	/**
	 * Sets the predicate that will be called before removing a tab via the gui close control. Note
	 * that that tab panel's default action is to remove the tab value, but if you set your own
	 * consumer, you have the responsibility to remove the value.
	 * @param closeTabConsumer the consumer called when the close gui control is clicked.
	 */
	public void setCloseTabConsumer(Consumer<T> closeTabConsumer) {
		this.closeTabConsumer = closeTabConsumer;
	}

	/**
	 * Sets the consumer to be notified when the selected tab changes.
	 * @param selectedTabConsumer the consumer to be notified when the selected tab changes
	 */
	public void setSelectedTabConsumer(Consumer<T> selectedTabConsumer) {
		this.selectedTabConsumer = selectedTabConsumer;
	}

	/**
	 * Returns true if the popup tab list is showing.
	 * @return true if the popup tab list is showing
	 */
	public boolean isShowingTabList() {
		return tabList != null;
	}

	/**
	 * Sets whether or not tabs should be display when there is only one tab. 
	 * @param b true to show one tab; false collapses tab panel when only one tab exists
	 */
	public void setShowTabsAlways(boolean b) {
		showTabsAlways = b;
		rebuildTabs();
	}

	/** 
	 * Returns the value of the tab that generated the given mouse event. If the mouse event
	 * is not from one of the tabs, then null is returned.
	 * @param event the MouseEvent to get a value for
	 * @return the value of the tab that generated the mouse event
	 */
	@SuppressWarnings("unchecked")
	public T getValueFor(MouseEvent event) {
		Object source = event.getSource();
		if (source instanceof JLabel label) {
			Container parent = label.getParent();
			if (parent instanceof GTab gTab) {
				return (T) gTab.getValue();
			}
		}
		return null;
	}

	void showTabList() {
		if (tabList != null) {
			return;
		}
		JComponent c = hasHiddenTabs() ? hiddenValuesControl : allTabs.get(allTabs.size() - 1);
		tabList = new TabListPopup<T>(this, c, tabTypeName);
		tabList.setVisible(true);
	}

	void closeTab(T value) {
		closeTabConsumer.accept(value);
	}

	private void selectHighlightedValue() {
		if (highlightedValue != null) {
			selectTab(highlightedValue);
		}
	}

	void highlightFromTabList(boolean forward) {
		closeTabList();
		int highlightIndex = forward ? 0 : allTabs.size() - 1;
		highlightTab(allTabs.get(highlightIndex).getValue());
		requestFocus();
	}

	private T getTabbedValueAfter(T current) {
		if (current == null) {
			return allTabs.get(0).getValue();
		}
		int tabIndex = getTabIndex(current);
		if (tabIndex >= 0 && tabIndex < allTabs.size() - 1) {
			return allTabs.get(tabIndex + 1).getValue();
		}
		if (hasHiddenTabs()) {
			return null;
		}
		return allTabs.get(0).getValue();
	}

	private T getTabbedValueBefore(T current) {
		if (current == null) {
			return allTabs.get(allTabs.size() - 1).getValue();
		}
		int tabIndex = getTabIndex(current);
		if (tabIndex >= 1) {
			return allTabs.get(tabIndex - 1).getValue();
		}
		if (hasHiddenTabs()) {
			return null;
		}
		return allTabs.get(allTabs.size() - 1).getValue();
	}

	private int getTabIndex(T value) {
		for (int i = 0; i < allTabs.size(); i++) {
			if (allTabs.get(i).getValue().equals(value)) {
				return i;
			}
		}
		return -1;
	}

	private void updateTabColors() {
		boolean tabPanelHasFocus = hasFocus();
		for (GTab<T> tab : allTabs) {
			T value = tab.getValue();
			tab.setHighlight(shouldHighlight(value, tabPanelHasFocus));
		}
	}

	private boolean shouldHighlight(T value, boolean tabPanelHasFocus) {
		if (value.equals(highlightedValue)) {
			return true;
		}
		if (tabPanelHasFocus && highlightedValue == null) {
			return value.equals(selectedValue);
		}
		return false;
	}

	private void doAddValue(T value) {
		Objects.requireNonNull(value);
		allValues.add(value);
	}

	private void rebuildTabs() {
		allTabs.clear();
		removeAll();
		closeTabList();
		setBorder(null);
		if (!shouldShowTabs()) {
			revalidate();
			repaint();
			return;
		}
		setBorder(new GTabPanelBorder());

		GTab<T> selectedTab = null;
		int availableWidth = getPanelWidth();
		if (selectedValue != null) {
			selectedTab = new GTab<T>(this, selectedValue, true);
			availableWidth -= getTabWidth(selectedTab);
		}
		createNonSelectedTabsForWidth(availableWidth);

		// a negative available width means there wasn't even enough room for the selected value tab
		if (selectedValue != null && availableWidth >= 0) {
			allTabs.add(getIndexToInsertSelectedValue(allTabs.size()), selectedTab);
		}

		// add tabs to this panel
		for (GTab<T> gTab : allTabs) {
			add(gTab);
		}

		// if there are hidden tabs add hidden value control to this panel
		if (hasHiddenTabs()) {
			hiddenValuesControl.setHiddenCount(allValues.size() - allTabs.size());
			add(hiddenValuesControl);
		}
		updateTabColors();
		updateAccessibleName();
		revalidate();
		repaint();
	}

	private boolean shouldShowTabs() {
		if (allValues.isEmpty()) {
			return false;
		}
		if (allValues.size() == 1 && !showTabsAlways) {
			return false;
		}
		return true;
	}

	private void updateAccessibleName() {
		getAccessibleContext().setAccessibleName(getAccessibleName());
	}

	String getAccessibleName() {
		StringBuilder builder = new StringBuilder(tabTypeName);
		builder.append(" Tab Panel: ");
		if (allValues.isEmpty()) {
			builder.append("No Tabs");
			return builder.toString();
		}
		if (selectedValue != null) {
			builder.append(getDisplayName(selectedValue));
			builder.append(" selected");
		}
		else {
			builder.append("No Selected Tab");
		}
		if (highlightedValue != null) {
			builder.append(": ");
			builder.append(getDisplayName(highlightedValue));
			builder.append(" highlighted");
		}
		return builder.toString();
	}

	private int getIndexToInsertSelectedValue(int maxIndex) {
		Iterator<T> it = allValues.iterator();
		for (int i = 0; i < maxIndex; i++) {
			T t = it.next();
			if (t == selectedValue) {
				return i;
			}
		}
		return maxIndex;
	}

	private void createNonSelectedTabsForWidth(int availableWidth) {
		for (T value : allValues) {
			if (value == selectedValue) {
				continue;
			}
			GTab<T> tab = new GTab<T>(this, value, false);

			int tabWidth = getTabWidth(tab);
			if (tabWidth > availableWidth) {
				break;
			}

			allTabs.add(tab);
			availableWidth -= tabWidth;
		}

		// remove last tab if there isn't room for hidden values control
		if (hasHiddenTabs() && availableWidth < hiddenValuesControl.getPreferredWidth()) {
			if (!allTabs.isEmpty()) {
				allTabs.remove(allTabs.size() - 1);
			}
		}
	}

	private int getTabWidth(GTab<T> tab) {
		return tab.getPreferredSize().width;
	}

	private int getPanelWidth() {
		return getSize().width;
	}

	boolean isListWindowShowing() {
		return tabList != null;
	}

	String getDisplayName(T t) {
		return nameFunction.apply(t);
	}

	Icon getValueIcon(T value) {
		return iconFunction.apply(value);
	}

	String getValueToolTip(T value) {
		return toolTipFunction.apply(value);
	}

	void tabListFocusLost() {
		if (!ignoreFocusLost) {
			closeTabList();
		}
	}

	void closeTabList() {
		if (tabList != null) {
			tabList.close();
			tabList = null;
		}
	}

	/*testing*/public void setIgnoreFocus(boolean ignoreFocusLost) {
		this.ignoreFocusLost = ignoreFocusLost;
	}

	/*testing*/public JPanel getTab(T value) {
		for (GTab<T> tab : allTabs) {
			if (tab.getValue().equals(value)) {
				return tab;
			}
		}
		return null;
	}

}
