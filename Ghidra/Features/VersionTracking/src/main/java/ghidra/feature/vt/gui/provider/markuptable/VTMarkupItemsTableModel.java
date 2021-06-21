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
package ghidra.feature.vt.gui.provider.markuptable;

import java.awt.Color;
import java.awt.Component;
import java.util.*;
import java.util.stream.Collectors;

import javax.swing.JLabel;

import docking.widgets.table.*;
import ghidra.app.util.SymbolInspector;
import ghidra.docking.settings.Settings;
import ghidra.feature.vt.api.impl.MarkupItemImpl;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.Stringable;
import ghidra.feature.vt.gui.editors.DisplayableAddress;
import ghidra.feature.vt.gui.editors.EditableAddress;
import ghidra.feature.vt.gui.filters.Filter;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.task.SetMarkupItemDestinationAddressTask;
import ghidra.feature.vt.gui.util.MatchInfo;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.column.*;
import ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn;
import ghidra.util.task.TaskMonitor;

public class VTMarkupItemsTableModel extends AddressBasedTableModel<VTMarkupItem> {

	private static final String TITLE = "VTMatchMarkupItem Table Model";

	private List<Filter<VTMarkupItem>> allFilters = new ArrayList<>();
	private final VTController controller;

	public VTMarkupItemsTableModel(VTController controller) {
		super(TITLE, controller.getServiceProvider(), controller.getSourceProgram(), null);
		this.controller = controller;
	}

	@Override
	protected TableColumnDescriptor<VTMarkupItem> createTableColumnDescriptor() {
		TableColumnDescriptor<VTMarkupItem> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(new StatusTableColumn());
		descriptor.addVisibleColumn(new SourceAddressTableColumn(), 1, true);
		descriptor.addVisibleColumn(new AppliedDestinationAddressTableColumn());
		descriptor.addHiddenColumn(new RelativeDisplacementTableColumn());
		descriptor.addVisibleColumn(new MarkupTypeTableColumn());
		descriptor.addVisibleColumn(new SourceValueTableColumn());
		descriptor.addVisibleColumn(new DestinationValueTableColumn());
		descriptor.addVisibleColumn(new OriginalDestinationValueTableColumn());
		if (SystemUtilities.isInDevelopmentMode()) {
			descriptor.addHiddenColumn(new AppliedDestinationSourceTableColumn());
			descriptor.addHiddenColumn(new IsInDBTableColumn());
		}

		return descriptor;
	}

	@Override
	public Address getAddress(int row) {
		VTMarkupItem markupItem = getRowObject(row);
		return markupItem.getSourceAddress();
	}

	@Override
	// overridden to force a clear of data before reloading (for painting responsiveness)
	public void reload() {
		reload(true);
	}

	void reload(boolean clearFirst) {
		if (clearFirst) {
			clearData();
		}
		super.reload();
	}

	@Override
	protected void doLoad(Accumulator<VTMarkupItem> accumulator, TaskMonitor monitor)
			throws CancelledException {
		MatchInfo matchInfo = controller.getMatchInfo();
		if (matchInfo == null) {
			return; // no match selected
		}

		Collection<VTMarkupItem> markupItems = matchInfo.getAppliableMarkupItems(monitor);
		if (markupItems == null) {
			return; // some sort of exception happened when loading the markup items
		}

		monitor.setMessage("Processing markup items");
		monitor.initialize(markupItems.size());

		for (VTMarkupItem markupItem : markupItems) {
			monitor.checkCanceled();
			accumulator.add(markupItem);
			monitor.incrementProgress(1);
		}
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		int appliedAddressIndex = getColumnIndex(AppliedDestinationAddressTableColumn.class);

		if (columnIndex != appliedAddressIndex) {
			return false;
		}

		// Make destination address editable. It will get validated upon edit and 
		// display an info dialog if not really editable.
		return true;
	}

	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		int appliedAddressIndex = getColumnIndex(AppliedDestinationAddressTableColumn.class);

		if (columnIndex != appliedAddressIndex) {
			return;
		}
		// Only column that can be set is the applied target address.
		Address destinationAddress = (Address) aValue;
		VTMarkupItem appliableMarkupItem = getRowObject(rowIndex);
		ArrayList<VTMarkupItem> items = new ArrayList<>();
		items.add(appliableMarkupItem);

		SetMarkupItemDestinationAddressTask task = new SetMarkupItemDestinationAddressTask(
			controller.getSession(), items, destinationAddress);
		controller.runVTTask(task);
		reload(false); // our row types may have changed
	}

	public void updateFilter() {
		rebuildFilter(); // this triggers a call to reFilter()
	}

	void addFilter(Filter<VTMarkupItem> filter) {
		allFilters.add(filter);
		rebuildFilter();
	}

	private void rebuildFilter() {

		//@formatter:off
		List<Filter<VTMarkupItem>> copiedFilters =
			allFilters.stream()
					  .map(f -> f.createCopy())
					  .collect(Collectors.toList())
					  ;
		//@formatter:on

		MarkupTablePassthroughFilter passThroughFilter =
			new MarkupTablePassthroughFilter(copiedFilters);
		setTableFilter(passThroughFilter);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================   

	private static class MarkupTablePassthroughFilter implements TableFilter<VTMarkupItem> {

		private List<Filter<VTMarkupItem>> appliedFilters;

		MarkupTablePassthroughFilter(List<Filter<VTMarkupItem>> appliedFilters) {
			this.appliedFilters = appliedFilters;
		}

		@Override
		public boolean acceptsRow(VTMarkupItem markup) {

			if (appliedFilters == null) {
				// null implies that all items will fail to filter, as one or more of the filters is
				// in a state where nothing will pass
				return false;
			}

			if (appliedFilters.isEmpty()) {
				return true;
			}

			if (rowMatchesFilters(appliedFilters, markup)) {
				return true;
			}

			return false;
		}

		/*
		 * For our row to match, each column must be tested for each filter to see if all filters 
		 * match, as we are using an AND filtering mechanism.
		 */
		private boolean rowMatchesFilters(List<Filter<VTMarkupItem>> filters,
				VTMarkupItem VTMarkupItem) {

			for (Filter<VTMarkupItem> filter : filters) {
				if (!filter.passesFilter(VTMarkupItem)) {
					return false; // if any filter doesn't match then we fail
				}
			}
			return true;
		}

		@Override
		public boolean isSubFilterOf(TableFilter<?> tableFilter) {

			if (!(tableFilter instanceof MarkupTablePassthroughFilter)) {
				return false;
			}

			MarkupTablePassthroughFilter otherMarkupFilter =
				(MarkupTablePassthroughFilter) tableFilter;
			if (appliedFilters.size() != otherMarkupFilter.appliedFilters.size()) {
				return false;
			}

			int n = appliedFilters.size();
			for (int i = 0; i < n; i++) {
				Filter<VTMarkupItem> myFilter = appliedFilters.get(i);
				Filter<VTMarkupItem> otherFilter = otherMarkupFilter.appliedFilters.get(i);
				if (!myFilter.isSubFilterOf(otherFilter)) {
					return false;
				}
			}
			return true;
		}

		@Override
		public int hashCode() {
			// not meant to put in hashing structures; the data for equals changes
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean equals(Object obj) {
			// For now we don't support equals(); if this filter gets re-created, 
			// then the table must be re-filtered.  If we decide to implement this method, then 
			// we must also implement equals() on the filters used by this filter.
			return this == obj;
		}
	}

	// column for selecting/editing?

	private static class SourceAddressTableColumn
			extends AbstractProgramBasedDynamicTableColumn<VTMarkupItem, DisplayableAddress> {

		private SymbolInspector symbolInspector;

		@Override
		public String getColumnName() {
			return "Source Address";
		}

		@Override
		public DisplayableAddress getValue(VTMarkupItem rowObject, Settings settings,
				Program program, ServiceProvider serviceProvider) throws IllegalArgumentException {
			if (symbolInspector == null) {
				symbolInspector = new SymbolInspector(serviceProvider, null);
			}
			VTAssociation association = rowObject.getAssociation();
			Program sourceProgram = association.getSession().getSourceProgram();
			DisplayableAddress displayableAddress;

//			VTMarkupType markupType = rowObject.getMarkupType();
//			if (markupType instanceof FunctionParameterMarkupType) {
//				Address sourceAddress = association.getSourceAddress();
//				Function function = sourceProgram.getFunctionManager().getFunctionAt(sourceAddress);
//				displayableAddress =
//					new DisplayableParameterAddress(function, rowObject.getSourceAddress());
//			}
//			else if (markupType instanceof FunctionLocalVariableMarkupType) {
//				Address sourceAddress = association.getSourceAddress();
//				Function function = sourceProgram.getFunctionManager().getFunctionAt(sourceAddress);
//				displayableAddress =
//					new DisplayableLocalVariableAddress(function, rowObject.getSourceAddress());
//			}
//			else {
			displayableAddress =
				new DisplayableListingAddress(sourceProgram, rowObject.getSourceAddress());
//			}
			return displayableAddress;
		}

		private AddressRenderer addressCellRenderer = new AddressRenderer();

		@Override
		public GColumnRenderer<DisplayableAddress> getColumnRenderer() {
			return addressCellRenderer;
		}

		@Override
		public int getColumnPreferredWidth() {
			return 75;
		}

		private class AddressRenderer extends AbstractGhidraColumnRenderer<DisplayableAddress> {

			@Override
			public Component getTableCellRendererComponent(GTableCellRenderingData data) {

				Object value = data.getValue();

				DisplayableAddress editableAddress = (DisplayableAddress) value;
				String addressString = editableAddress.getDisplayString();

				GTableCellRenderingData renderData = data.copyWithNewValue(addressString);

				JLabel renderer = (JLabel) super.getTableCellRendererComponent(renderData);

				Program program = editableAddress.getProgram();
				Address address = editableAddress.getAddress();
				Symbol s = null;
				if (address != null && address != Address.NO_ADDRESS && symbolInspector != null) {
					s = program.getSymbolTable().getPrimarySymbol(address);
				}
				Color c = Color.RED;
				if (symbolInspector != null) {
					symbolInspector.setProgram(program);
					c = symbolInspector.getColor(s);
				}
				setForeground(c);

				renderer.setOpaque(true);

				return renderer;
			}

			@Override
			public String getFilterString(DisplayableAddress t, Settings settings) {
				return t.getDisplayString();
			}
		}
	}

	private static class RelativeDisplacementTableColumn
			extends AbstractProgramBasedDynamicTableColumn<VTMarkupItem, Long> {

		@Override
		public String getColumnName() {
			return "Displacement";
		}

		@Override
		public Long getValue(VTMarkupItem markupItem, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {

			Address sourceAddress = markupItem.getSourceAddress();
			Address destinationAddress = markupItem.getDestinationAddress();
			if (destinationAddress == null || destinationAddress == Address.NO_ADDRESS) {
				return null;
			}

//			VTMarkupType markupType = markupItem.getMarkupType();
//			if ((markupType instanceof FunctionParameterMarkupType) ||
//				(markupType instanceof FunctionLocalVariableMarkupType)) {
//				return Long.valueOf(0);
//			}

			VTAssociation association = markupItem.getAssociation();
			Address sourceMatchAddress = association.getSourceAddress();
			Address destinationMatchAddress = association.getDestinationAddress();

			long relativeSourceOffset = sourceAddress.subtract(sourceMatchAddress);
			long relativeDestinationOffset = destinationAddress.subtract(destinationMatchAddress);
			return relativeDestinationOffset - relativeSourceOffset;

		}

		@Override
		public int getColumnPreferredWidth() {
			return 50;
		}

		@Override
		public String getColumnDescription() {
			return "Displays relative displacement of the destination address as compared to the source\n" +
				" address.  Positive numbers indicated additions in the destination and\n" +
				" negative numbers indicate subtractions.";
		}
	}

	static class AppliedDestinationAddressTableColumn
			extends AbstractProgramBasedDynamicTableColumn<VTMarkupItem, EditableAddress> {

		private SymbolInspector symbolInspector;

		private AddressRenderer addressCellRenderer = new AddressRenderer();

		@Override
		public String getColumnName() {
			return "Dest Address";
		}

		@Override
		public EditableAddress getValue(VTMarkupItem rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			VTAssociation association = rowObject.getAssociation();
			Program destinationProgram = association.getSession().getDestinationProgram();
			if (symbolInspector == null) {
				symbolInspector = new SymbolInspector(serviceProvider, null);
			}
			EditableAddress editableAddress;

//			VTMarkupType markupType = rowObject.getMarkupType();
			Address destinationAddress = rowObject.getDestinationAddress();
//			if (markupType instanceof FunctionParameterMarkupType) {
//				Address associationDestinationAddress = association.getDestinationAddress();
//				Function function =
//					destinationProgram.getFunctionManager().getFunctionAt(
//						associationDestinationAddress);
//				editableAddress =
//					new EditableParameterAddress(function, destinationAddress, rowObject);
//			}
//			else {
			editableAddress =
				new EditableListingAddress(destinationProgram, destinationAddress, rowObject);
//			}
			return editableAddress;
		}

		@Override
		public GColumnRenderer<EditableAddress> getColumnRenderer() {
			return addressCellRenderer;
		}

		@Override
		public int getColumnPreferredWidth() {
			return 75;
		}

		private class AddressRenderer extends AbstractGhidraColumnRenderer<EditableAddress> {

			@Override
			public Component getTableCellRendererComponent(GTableCellRenderingData data) {

				Object value = data.getValue();

				EditableAddress editableAddress = (EditableAddress) value;
				String addressString = editableAddress.getDisplayString();

				GTableCellRenderingData renderData = data.copyWithNewValue(addressString);

				JLabel renderer = (JLabel) super.getTableCellRendererComponent(renderData);

				Program program = editableAddress.getProgram();
				Address address = editableAddress.getAddress();
				Symbol s = null;
				if (address != null && address != Address.NO_ADDRESS && symbolInspector != null) {
					s = program.getSymbolTable().getPrimarySymbol(address);
				}
				Color c = Color.RED;
				if (symbolInspector != null) {
					symbolInspector.setProgram(program);
					c = symbolInspector.getColor(s);
				}
				setForeground(c);

				renderer.setOpaque(true);

				return renderer;
			}

			@Override
			public String getFilterString(EditableAddress t, Settings settings) {
				return t.getDisplayString();
			}
		}
	}

	static class AppliedDestinationSourceTableColumn
			extends AbstractProgramBasedDynamicTableColumn<VTMarkupItem, String> {

		private static final String NO_SOURCE_TEXT = "None";

		private GColumnRenderer<String> sourceCellRenderer = new AbstractGColumnRenderer<>() {
			@Override
			public Component getTableCellRendererComponent(GTableCellRenderingData data) {

				Object value = data.getValue();
				boolean isSelected = data.isSelected();

				String addressSource = (value != null) ? (String) value : NO_SOURCE_TEXT;
				String sourceString = getText(value);

				GTableCellRenderingData renderData = data.copyWithNewValue(sourceString);

				JLabel renderer = (JLabel) super.getTableCellRendererComponent(renderData);

				if (NO_SOURCE_TEXT.equals(addressSource)) {
					setForeground(Color.RED);
				}
				else if (VTMarkupItem.USER_DEFINED_ADDRESS_SOURCE.equals(addressSource)) {
					setForeground(isSelected ? Color.CYAN : Color.CYAN.darker());
				}

				renderer.setOpaque(true);

				return renderer;
			}

			private String getText(String value) {
				String addressSource = (value != null) ? (String) value : NO_SOURCE_TEXT;
				String sourceString = "(" + addressSource + ")";
				return sourceString;
			}

			@Override
			public String getFilterString(String t, Settings settings) {
				return getText(t);
			}
		};

		@Override
		public String getColumnName() {
			return "Dest Address Source";
		}

		@Override
		public String getValue(VTMarkupItem rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			String destinationAddressSource = rowObject.getDestinationAddressSource();
			return destinationAddressSource;
		}

		@Override
		public GColumnRenderer<String> getColumnRenderer() {
			return sourceCellRenderer;
		}

		@Override
		public int getColumnPreferredWidth() {
			return 75;
		}

	}

	static class IsInDBTableColumn
			extends AbstractProgramBasedDynamicTableColumn<VTMarkupItem, Boolean> {

		private GColumnRenderer<Boolean> isInDBCellRenderer = new AbstractGColumnRenderer<>() {
			@Override
			public Component getTableCellRendererComponent(GTableCellRenderingData data) {

				Object value = data.getValue();

				boolean isInDB = ((Boolean) value).booleanValue();

				GTableCellRenderingData renderData = data.copyWithNewValue(isInDB ? "yes" : null);

				JLabel renderer = (JLabel) super.getTableCellRendererComponent(renderData);
				renderer.setOpaque(true);

				return renderer;
			}

			@Override
			public String getFilterString(Boolean t, Settings settings) {
				boolean isInDB = t.booleanValue();
				return isInDB ? "yes" : "";
			}
		};

		@Override
		public String getColumnName() {
			return "In DB?";
		}

		@Override
		public Boolean getValue(VTMarkupItem rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {

			if (!(rowObject instanceof MarkupItemImpl)) {
				return false;
			}
			MarkupItemImpl impl = (MarkupItemImpl) rowObject;
			return impl.isStoredInDB();
		}

		@Override
		public GColumnRenderer<Boolean> getColumnRenderer() {
			return isInDBCellRenderer;
		}

		@Override
		public int getColumnPreferredWidth() {
			return 25;
		}
	}

	private static class MarkupTypeTableColumn
			extends AbstractProgramBasedDynamicTableColumn<VTMarkupItem, String> {

		@Override
		public String getColumnName() {
			return "Markup Type";
		}

		@Override
		public String getValue(VTMarkupItem rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getMarkupType().getDisplayName();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}
	}

	private class SourceValueTableColumn
			extends AbstractProgramBasedDynamicTableColumn<VTMarkupItem, Stringable> {

		private MarkupItemValueRenderer renderer;

		@Override
		public String getColumnName() {
			return "Source Value";
		}

		@Override
		public String getColumnDescription() {
			return "The current source value for the markup item.";
		}

		@Override
		public Stringable getValue(VTMarkupItem rowObject, Settings settings, Program theProgram,
				ServiceProvider theServiceProvider) throws IllegalArgumentException {
			return rowObject.getSourceValue();
		}

		@Override
		public GColumnRenderer<Stringable> getColumnRenderer() {
			if (renderer == null) {
				renderer = new MarkupItemValueRenderer();
			}
			return renderer;
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}
	}

	private class DestinationValueTableColumn
			extends AbstractProgramBasedDynamicTableColumn<VTMarkupItem, Stringable> {

		private MarkupItemValueRenderer renderer;

		@Override
		public String getColumnName() {
			return "Current Dest Value";
		}

		@Override
		public String getColumnDescription() {
			return "The current destination value for the markup item.";
		}

		@Override
		public Stringable getValue(VTMarkupItem rowObject, Settings settings, Program theProgram,
				ServiceProvider theServiceProvider) throws IllegalArgumentException {
			return rowObject.getCurrentDestinationValue();
		}

		@Override
		public GColumnRenderer<Stringable> getColumnRenderer() {
			if (renderer == null) {
				renderer = new MarkupItemValueRenderer();
			}
			return renderer;
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}
	}

	private class OriginalDestinationValueTableColumn
			extends AbstractProgramBasedDynamicTableColumn<VTMarkupItem, Stringable> {

		private MarkupItemValueRenderer renderer;

		@Override
		public String getColumnName() {
			return "Original Dest Value";
		}

		@Override
		public String getColumnDescription() {
			return "The original destination value for the markup item.";
		}

		@Override
		public Stringable getValue(VTMarkupItem rowObject, Settings settings, Program theProgram,
				ServiceProvider theServiceProvider) throws IllegalArgumentException {
			return rowObject.getOriginalDestinationValue();
		}

		@Override
		public GColumnRenderer<Stringable> getColumnRenderer() {
			if (renderer == null) {
				renderer = new MarkupItemValueRenderer();
			}
			return renderer;
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}
	}

	private static class StatusTableColumn
			extends AbstractProgramBasedDynamicTableColumn<VTMarkupItem, VTMarkupItemStatus> {

		private MarkupItemStatusRenderer renderer = new MarkupItemStatusRenderer();

		@Override
		public String getColumnName() {
			return "Status";
		}

		@Override
		public VTMarkupItemStatus getValue(VTMarkupItem rowObject, Settings settings,
				Program program, ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getStatus();
		}

		@Override
		public GColumnRenderer<VTMarkupItemStatus> getColumnRenderer() {
			return renderer;
		}

		@Override
		public int getColumnPreferredWidth() {
			return 30;
		}
	}
}
