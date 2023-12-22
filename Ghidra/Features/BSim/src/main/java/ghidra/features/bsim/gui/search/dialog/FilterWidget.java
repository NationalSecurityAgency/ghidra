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

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import javax.swing.*;

import docking.widgets.EmptyBorderButton;
import docking.widgets.combobox.GhidraComboBox;
import ghidra.features.bsim.gui.filters.BSimFilterType;
import ghidra.features.bsim.gui.filters.BSimValueEditor;
import ghidra.util.Swing;
import resources.Icons;
import utility.function.Callback;

/**
 * This class defines a widget for a single BSim filter. At a minimum
 * it will consist of a combobox containing the available filters. It may optionally
 * contain a secondary widget for specifying filter values. This secondary widget
 * is filter-specific; for most filter types it will be a text entry field but as long
 * as it implements the {@link FilterContent} interface it is valid.
 * 
 */
public class FilterWidget extends JPanel {
	private GhidraComboBox<BSimFilterType> filterComboBox;
	private JPanel contentPanel;

	private BSimFilterType filterType;
	private BSimValueEditor editor;

	private ItemListener comboChangeListener = this::comboChanged;
	private Callback changeListener;

	/**
	 * Constructs a new filter widget.
	 * @param filterTypes The list of filter types that can be chosen
	 * @param removeConsumer the container to be notified that it should delete this object
	 * @param renameListener listener to be notified when filter value changes
	 */
	public FilterWidget(List<BSimFilterType> filterTypes, Consumer<FilterWidget> removeConsumer,
			Callback changeListener) {

		this.changeListener = changeListener;
		this.filterType = filterTypes.get(0); // the first is the blank filter

		setLayout(new BorderLayout());
		add(createFilterComboBox(filterTypes), BorderLayout.WEST);
		add(buildFilterContentPanel(), BorderLayout.CENTER);
		add(buildDeleteButton(removeConsumer), BorderLayout.EAST);

	}

	public void setFilters(List<BSimFilterType> filters) {
		if (filters == null || filters.isEmpty()) {
			filters = List.of(BSimFilterType.BLANK);
		}

		filterComboBox.removeItemListener(comboChangeListener);

		DefaultComboBoxModel<BSimFilterType> model = new DefaultComboBoxModel<>();
		model.addAll(filters);
		filterComboBox.setModel(model);

		if (filterType == null || !filters.contains(filterType)) {
			filterType = filters.get(0);
			createInputField(filterType);
		}
		filterComboBox.setSelectedItem(filterType);

		filterComboBox.addItemListener(comboChangeListener);
	}

	public void setFilter(BSimFilterType filter, List<String> values) {
		ComboBoxModel<BSimFilterType> model = filterComboBox.getModel();
		for (int i = 0; i < model.getSize(); i++) {
			BSimFilterType newFilterType = model.getElementAt(i);
			if (filter.equals(newFilterType)) {
				filterComboBox.setSelectedIndex(i);
				editor.setValues(values);
				break;
			}
		}
	}

	/**
	 * Returns the selected filter.
	 * @return the filter
	 */
	public BSimFilterType getSelectedFilter() {
		return filterType;
	}

	/**
	 * Returns all values in the filter as a list. For filters that do not allow
	 * multiple entries, this will always return a list of only one item.
	 * 
	 * @return filter values
	 * 
	 */
	public List<String> getValues() {
		return editor.getValues();
	}

	private void createInputField(BSimFilterType filter) {
		contentPanel.removeAll();
		editor = createEditor(filter, null);
		contentPanel.add(editor.getComponent(), BorderLayout.CENTER);
		revalidate();
	}

	private BSimValueEditor createEditor(BSimFilterType filter, List<String> initialValues) {
		if (filter == null) {
			return null;
		}
		return filter.getEditor(initialValues, changeListener);
	}

	private GhidraComboBox<BSimFilterType> createFilterComboBox(List<BSimFilterType> filters) {
		filterComboBox = new GhidraComboBox<>();
		setFilters(filters);
		return filterComboBox;
	}

	private Component buildDeleteButton(Consumer<FilterWidget> removeConsumer) {
		JButton deleteButton = new EmptyBorderButton(Icons.DELETE_ICON);
		deleteButton.setToolTipText("Delete filter");
		deleteButton.setName("Delete Filter");
		deleteButton.addActionListener(e -> {
			removeConsumer.accept(this);
		});
		return deleteButton;
	}

	private Component buildFilterContentPanel() {
		editor = createEditor(filterType, null);
		contentPanel = new JPanel(new BorderLayout());
		contentPanel.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 10));
		contentPanel.add(editor.getComponent());
		return contentPanel;
	}

	private void comboChanged(ItemEvent e) {
		if (e.getStateChange() == ItemEvent.SELECTED) {
			filterType = (BSimFilterType) e.getItem();
			createInputField(filterType);
			notifyChangeListener();
		}
	}

	private void notifyChangeListener() {
		Swing.runLater(() -> changeListener.call());
	}

	public boolean isBlank() {
		return filterType.isBlank();
	}

	public boolean hasValidValue() {
		return editor.hasValidValues();
	}
//==================================================================================================
// Test methods
//==================================================================================================

	List<BSimFilterType> getChoosableFilterTypes() {
		ComboBoxModel<BSimFilterType> model = filterComboBox.getModel();
		List<BSimFilterType> types = new ArrayList<>();
		for (int i = 0; i < model.getSize(); i++) {
			types.add(model.getElementAt(i));
		}
		return types;
	}
}
