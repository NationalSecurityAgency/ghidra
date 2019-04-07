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
package ghidra.feature.vt.gui.filters;

import static ghidra.feature.vt.gui.filters.Filter.FilterEditingStatus.APPLIED;
import static ghidra.feature.vt.gui.filters.Filter.FilterEditingStatus.NONE;

import java.awt.Container;
import java.awt.LayoutManager;
import java.util.*;
import java.util.stream.Collectors;

import javax.swing.*;

import ghidra.framework.options.SaveState;
import ghidra.util.layout.ColumnLayout;
import ghidra.util.layout.VerticalLayout;

/**
 * A basic class to extract out code I was repeating over and over again.  This class creates
 * a component that contains series of check boxes and can answer questions about filtering.
 * 
 * @param <T> the type of item being filtered
 */
public abstract class CheckBoxBasedAncillaryFilter<T> extends AncillaryFilter<T> {

	private JComponent component;
	protected Set<CheckBoxInfo<T>> checkBoxInfos =
		new TreeSet<CheckBoxInfo<T>>(new CheckBoxInfoComparator());
	private Set<String> enabledCheckBoxNames;
	private final String filterName;

	public CheckBoxBasedAncillaryFilter(String filterName) {
		this.filterName = filterName;
		createCheckBoxInfos();
		component = createComponent();
	}

	protected abstract void createCheckBoxInfos();

	// overridden to clear cache
	@Override
	public void fireFilterStateChanged() {

		enabledCheckBoxNames = null;
		super.fireFilterStateChanged();
	}

	private Set<String> initializeEnabledCheckBoxNames() {
		if (enabledCheckBoxNames == null) {
			//@formatter:off
			enabledCheckBoxNames =
				checkBoxInfos.stream()
							 .filter(info -> info.isSelected())
							 .map(info -> info.getCheckBox().getText())
							 .collect(Collectors.toSet())
							 ;
			//@formatter:on
		}
		return enabledCheckBoxNames;
	}

	public Set<String> getEnabledFilterNames() {
		return initializeEnabledCheckBoxNames();
	}

	protected JComponent createComponent() {
		LayoutManager manager = createLayoutManager();
		JPanel panel = new JPanel();
		panel.setLayout(manager);
		panel.setBorder(BorderFactory.createTitledBorder(filterName));

		addCheckBoxes(panel);

		return createFilterPanel(panel);
	}

	protected JPanel createFilterPanel(JPanel checkBoxPanel) {
		return checkBoxPanel; // this method is for subclasses to override
	}

	private LayoutManager createLayoutManager() {
		int maxColumnThreshold = 7;
		LayoutManager manager = checkBoxInfos.size() <= maxColumnThreshold ? new VerticalLayout(1)
				: new ColumnLayout(1, 1, 2);
		return manager;
	}

	private void addCheckBoxes(Container container) {
		for (CheckBoxInfo<T> info : checkBoxInfos) {
			container.add(info.getCheckBox());
		}
	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	@Override
	public FilterEditingStatus getFilterStatus() {
		for (CheckBoxInfo<T> info : checkBoxInfos) {
			if (!info.isSelected()) {
				return APPLIED;
			}
		}

		return NONE;
	}

	@Override
	public boolean passesFilter(T t) {
		for (CheckBoxInfo<T> info : checkBoxInfos) {
			if (info.matchesStatus(t)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public FilterShortcutState getFilterShortcutState() {
		int onCount = 0;
		for (CheckBoxInfo<T> info : checkBoxInfos) {
			if (info.isSelected()) {
				onCount++;
			}
		}

		if (onCount == 0) {
			return FilterShortcutState.NEVER_PASSES;
		}

		if (onCount == checkBoxInfos.size()) {
			return FilterShortcutState.ALWAYS_PASSES;
		}

		return FilterShortcutState.REQUIRES_CHECK;
	}

	@Override
	public void clearFilter() {
		for (CheckBoxInfo<T> info : checkBoxInfos) {
			info.setSelected(true);
		}
	}

	@Override
	public FilterState getFilterState() {
		FilterState state = new FilterState(this);
		for (CheckBoxInfo<T> info : checkBoxInfos) {
			JCheckBox checkBox = info.getCheckBox();
			state.put(checkBox.getText(), checkBox.isSelected());
		}
		return state;
	}

	@Override
	public void restoreFilterState(FilterState state) {
		for (CheckBoxInfo<T> info : checkBoxInfos) {
			JCheckBox checkBox = info.getCheckBox();
			checkBox.setSelected((Boolean) state.get(checkBox.getText()));
		}
	}

	@Override
	public void readConfigState(SaveState saveState) {
		String[] values = saveState.getStrings(getStateKey(), null);
		if (values == null) {
			return; // nothing to restore
		}

		Map<String, CheckBoxInfo<T>> nameToInfoMap = createNameToInfoMap();
		for (String value : values) {
			String[] nameAndState = value.split(":");
			String name = nameAndState[0];
			CheckBoxInfo<T> info = nameToInfoMap.get(name);
			if (info == null) {
				continue; // no longer exists?
			}

			String state = nameAndState[1];
			JCheckBox checkBox = info.getCheckBox();
			checkBox.setSelected(Boolean.parseBoolean(state));
		}
	}

	private Map<String, CheckBoxInfo<T>> createNameToInfoMap() {
		Map<String, CheckBoxInfo<T>> map = new HashMap<String, CheckBoxInfo<T>>();
		for (CheckBoxInfo<T> info : checkBoxInfos) {
			map.put(info.getCheckBox().getText(), info);
		}
		return map;
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		String[] values = new String[checkBoxInfos.size()];
		int i = 0;
		for (CheckBoxInfo<T> info : checkBoxInfos) {
			JCheckBox checkBox = info.getCheckBox();
			String text = checkBox.getText();
			values[i++] = text + ":" + Boolean.toString(checkBox.isSelected());
		}

		String key = getStateKey();
		saveState.putStrings(key, values);
	}

	private String getStateKey() {
		return CheckBoxBasedAncillaryFilter.class.getSimpleName() + ":" + getClass().getName();
	}

	@Override
	public boolean isSubFilterOf(Filter<T> otherFilter) {

		Class<?> clazz = getClass();
		Class<?> otherClazz = otherFilter.getClass();
		if (!clazz.equals(otherClazz)) {
			return false; // must be the same class
		}

		CheckBoxBasedAncillaryFilter<?> otherCheckboxFilter =
			(CheckBoxBasedAncillaryFilter<?>) otherFilter;
		Set<String> names = getEnabledFilterNames();
		Set<String> otherNames = otherCheckboxFilter.getEnabledFilterNames();

		// 
		// This filter is a collection of 'things', that are allowed to pass the filter.   We are
		// only a sub-filter if the other filter has all of our 'things'.  Suppose our filter 
		// consists of: 'cat', 'dog'.  We would then be a sub-filter if the other filter's set 
		// consists of: 'cat', 'dog', and 'mouse', since our items will be in the results of 
		// that filter.
		//
		if (otherNames.containsAll(names)) {
			return true;
		}

		return false;
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + " " + getEnabledFilterNames();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class CheckBoxInfoComparator implements Comparator<CheckBoxInfo<T>> {

		@Override
		public int compare(CheckBoxInfo<T> o1, CheckBoxInfo<T> o2) {
			JCheckBox checkBox1 = o1.getCheckBox();
			JCheckBox checkBox2 = o2.getCheckBox();
			String text1 = checkBox1.getText();
			String text2 = checkBox2.getText();
			return text1.compareToIgnoreCase(text2);
		}
	}
}
