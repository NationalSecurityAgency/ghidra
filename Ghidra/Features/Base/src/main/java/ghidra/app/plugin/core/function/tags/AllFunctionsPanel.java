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
package ghidra.app.plugin.core.function.tags;

import java.awt.BorderLayout;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.*;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.table.GTableFilterPanel;
import docking.widgets.table.columnfilter.ColumnBasedTableFilter;
import docking.widgets.table.columnfilter.LogicOperation;
import docking.widgets.table.constraint.*;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.listing.*;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.field.AddressBasedLocation;

/**
 * Displays all functions that are associated with the selected tag in the
 * {@link SourceTagsPanel}
 */
public class AllFunctionsPanel extends JPanel {

	private FunctionTableModel model;
	private FunctionTableModel filteredModel;
	private JLabel titleLabel;
	private String filterText;
	private GhidraTable table;

	/**
	 * Constructor
	 * 
	 * @param program the current program
	 * @param provider the component provider
	 * @param title the title of the panel
	 */
	public AllFunctionsPanel(Program program, ComponentProviderAdapter provider, String title) {

		model = new FunctionTableModel(title, provider.getTool(), program, null);
		filteredModel = new FunctionTableModel(title, provider.getTool(), program, null);

		table = new GhidraTable(filteredModel);
		setLayout(new BorderLayout());

		titleLabel = new JLabel(title);
		titleLabel.setBorder(BorderFactory.createEmptyBorder(3, 5, 0, 0));

		add(titleLabel, BorderLayout.NORTH);
		add(new JScrollPane(table), BorderLayout.CENTER);

		GoToService goToService = provider.getTool().getService(GoToService.class);
		if (goToService != null) {
			table.installNavigation(goToService, goToService.getDefaultNavigatable());
		}
	}

	/**
	 * Filters the table based on the given text
	 * <p>
	 * Note that this panel shares a filter with the other panels in the 
	 * function tag dialog, so it doesn't use a dedicated 
	 * {@link GTableFilterPanel}.
	 * 
	 * @param filterString the filter text
	 */
	public void setFilterText(String filter) {
		this.filterText = filter;
		applyFilter();
	}

	/**
	 * Updates the table with whatever is in the {@link #model}
	 */
	public void refresh() {
		applyFilter();
		filteredModel.refresh();
	}

	/**
	 * Updates the table with functions containing the selected tags given
	 * 
	 * @param selectedTags the selected function tags
	 */
	public void refresh(List<FunctionTag> selectedTags) {
		setSelectedTags(selectedTags);
	}

	/**
	 * Stores the current program
	 * 
	 * @param program the current program
	 */
	public void setProgram(Program program) {
		model.setProgram(program);
		filteredModel.setProgram(program);
	}

	/**
	 * Updates the panel with the set of tags selected by the user. This
	 * will update the panel title and the contents of the function table.
	 * 
	 * @param tags the selected tags
	 */
	public void setSelectedTags(List<FunctionTag> tags) {
		String tagNames = tags.stream()
				.map(t -> t.getName())
				.collect(Collectors.joining(" or "))
				.toString();

		titleLabel.setText("Functions With Tag: " + tagNames);
		model.setSelectedTags(tags);
		filteredModel.setSelectedTags(tags);
		applyFilter();
	}

	/**
	 * Returns the list of functions in the panel
	 * <p>
	 * This is only used for testing!
	 * 
	 * @return  the list of functions
	 */
	public List<Function> getFunctions() {
		return model.getFunctions();
	}

	/**
	 * Returns the functions table model
	 * 
	 * @return the functions table model
	 */
	public FunctionTableModel getTableModel() {
		return model;
	}

	private void applyFilter() {
		if (StringUtils.isEmpty(filterText)) {
			return;
		}

		ColumnBasedTableFilter<Function> tableFilter = new ColumnBasedTableFilter<>(filteredModel);
		tableFilter.addConstraintSet(LogicOperation.OR, 0,
			Arrays.asList(new StringContainsColumnConstraint(filterText)));
		tableFilter.addConstraintSet(LogicOperation.OR, 1, Arrays.asList(
			new LocationContainsColumnConstraint(new StringContainsColumnConstraint(filterText))));
		tableFilter.addConstraintSet(LogicOperation.OR, 2,
			Arrays.asList(new StringContainsColumnConstraint(filterText)));

		filteredModel.setTableFilter(tableFilter);
		filteredModel.reFilter();
	}

	/**
	 * Converts an {@link AddressBasedLocation} to a string
	 */
	private class LocationToStringMapper
			extends ColumnTypeMapper<AddressBasedLocation, String> {

		@Override
		public String convert(AddressBasedLocation value) {
			return value.toString();
		}

	}

	/**
	 * Column constraint stipulating that a given {@link AddressBasedLocation}
	 * contains a specified string
	 */
	private class LocationContainsColumnConstraint
			extends MappedColumnConstraint<AddressBasedLocation, String> {

		public LocationContainsColumnConstraint(ColumnConstraint<String> delegate) {
			super(new LocationToStringMapper(), delegate);
		}

		@Override
		public ColumnConstraint<AddressBasedLocation> copy(ColumnConstraint<String> value) {
			return new LocationContainsColumnConstraint(value);
		}
	}
}
