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
package ghidra.app.plugin.core.strings;

import java.util.HashMap;
import java.util.Map;

import docking.widgets.table.DynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.app.plugin.core.string.translate.ManualStringTranslationService;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.util.StringUtilities;
import ghidra.util.Swing;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.table.field.AbstractProgramLocationTableColumn;
import ghidra.util.table.field.AddressBasedLocation;
import ghidra.util.task.TaskMonitor;

/**
 * Table model for the "Defined Strings" table.
 * <p>
 * This implementation keeps a local index of Address to row object (which are ProgramLocations)
 * so that DomainObjectChangedEvent events can be efficiently handled.
 */
class ViewStringsTableModel extends AddressBasedTableModel<ProgramLocation> {

	private Map<Address, ProgramLocation> rowsIndexedByAddress = new HashMap<>();

	/**
	 * Columns defined by this table (useful for enum.ordinal())
	 */
	public enum COLUMNS {
		ADDRESS_COL,
		STRING_VALUE_COL,
		STRING_REP_COL,
		DATA_TYPE_COL,
		IS_ASCII_COL,
		CHARSET_COL,
		HAS_ENCODING_ERROR
	}

	ViewStringsTableModel(PluginTool tool) {
		super("Defined String Table", tool, null, null);
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		DynamicTableColumn<ProgramLocation, ?, ?> column = getColumn(columnIndex);

		return (column instanceof StringRepColumn);
	}

	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		DynamicTableColumn<ProgramLocation, ?, ?> column = getColumn(columnIndex);
		if (column instanceof StringRepColumn) {
			ProgramLocation progLoc = getRowObject(rowIndex);
			ManualStringTranslationService.setTranslatedValue(program, progLoc, aValue.toString());
		}
	}

	@Override
	protected TableColumnDescriptor<ProgramLocation> createTableColumnDescriptor() {
		TableColumnDescriptor<ProgramLocation> descriptor = new TableColumnDescriptor<>();

		// These columns need to match the COLUMNS enum indexes
		descriptor.addVisibleColumn(new DataLocationColumn(), 1, true);
		descriptor.addVisibleColumn(new DataValueColumn());
		descriptor.addVisibleColumn(new StringRepColumn());
		descriptor.addVisibleColumn(new DataTypeColumn());
		descriptor.addHiddenColumn(new IsAsciiColumn());
		descriptor.addHiddenColumn(new CharsetColumn());
		descriptor.addHiddenColumn(new HasEncodingErrorColumn());

		return descriptor;
	}

	@Override
	protected void doLoad(Accumulator<ProgramLocation> accumulator, TaskMonitor monitor)
			throws CancelledException {
		rowsIndexedByAddress.clear();

		Program localProgram = getProgram();
		if (localProgram == null) {
			return;
		}

		Listing listing = localProgram.getListing();

		monitor.setCancelEnabled(true);
		monitor.initialize(listing.getNumDefinedData());
		Swing.allowSwingToProcessEvents();
		for (Data stringInstance : DefinedDataIterator.definedStrings(localProgram)) {
			accumulator.add(createIndexedStringInstanceLocation(localProgram, stringInstance));
			monitor.checkCanceled();
			monitor.incrementProgress(1);
		}
	}

	private ProgramLocation createIndexedStringInstanceLocation(Program localProgram, Data data) {
		ProgramLocation pl = new ProgramLocation(localProgram, data.getMinAddress(),
			data.getComponentPath(), null, 0, 0, 0);
		rowsIndexedByAddress.put(data.getMinAddress(), pl);
		return pl;
	}

	public void removeDataInstanceAt(Address addr) {
		ProgramLocation progLoc = rowsIndexedByAddress.get(addr);
		if (progLoc != null) {
			removeObject(progLoc);
		}
	}

	public ProgramLocation findEquivProgramLocation(ProgramLocation pl) {
		return (pl != null) ? rowsIndexedByAddress.get(pl.getAddress()) : null;
	}

	public void addDataInstance(Program localProgram, Data data, TaskMonitor monitor) {
		for (Data stringInstance : DefinedDataIterator.definedStrings(data)) {
			addObject(createIndexedStringInstanceLocation(localProgram, stringInstance));
		}
	}

	@Override
	public ProgramSelection getProgramSelection(int[] rows) {
		AddressSet set = new AddressSet();
		for (int element : rows) {
			ProgramLocation progLoc = filteredData.get(element);
			Data data = getProgram().getListing().getDataContaining(progLoc.getAddress());
			data = data.getComponent(progLoc.getComponentPath());
			set.addRange(data.getMinAddress(), data.getMaxAddress());
		}
		return new ProgramSelection(set);
	}

	public void reload(Program newProgram) {
		setProgram(newProgram);
		reload();
	}

	@Override
	public Address getAddress(int row) {
		return getRowObject(row).getAddress();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private static class DataLocationColumn
			extends AbstractProgramLocationTableColumn<ProgramLocation, AddressBasedLocation> {

		@Override
		public String getColumnName() {
			return "Location";
		}

		@Override
		public AddressBasedLocation getValue(ProgramLocation rowObject, Settings settings,
				Program program, ServiceProvider serviceProvider) throws IllegalArgumentException {
			return new AddressBasedLocation(rowObject.getProgram(), rowObject.getAddress());

		}

		@Override
		public ProgramLocation getProgramLocation(ProgramLocation rowObject, Settings settings,
				Program program, ServiceProvider serviceProvider) {
			return rowObject;
		}

	}

	// data value to string column (see the DataDataKeyModel)
	private static class DataValueColumn
			extends AbstractProgramLocationTableColumn<ProgramLocation, StringDataInstance> {

		private DataValueCellRenderer renderer = new DataValueCellRenderer();

		@Override
		public String getColumnName() {
			return "String Value";
		}

		@Override
		public StringDataInstance getValue(ProgramLocation rowObject, Settings settings,
				Program program, ServiceProvider serviceProvider) throws IllegalArgumentException {
			return StringDataInstance.getStringDataInstance(
				DataUtilities.getDataAtLocation(rowObject));
		}

		@Override
		public ProgramLocation getProgramLocation(ProgramLocation rowObject, Settings settings,
				Program program, ServiceProvider serviceProvider) {
			return rowObject;
		}

		@Override
		public GColumnRenderer<StringDataInstance> getColumnRenderer() {
			return renderer;
		}

		private class DataValueCellRenderer extends AbstractGColumnRenderer<StringDataInstance> {

			@Override
			protected String getText(Object value) {
				if (value instanceof StringDataInstance) {
					return ((StringDataInstance) value).toString();
				}
				return "";
			}

			@Override
			public String getFilterString(StringDataInstance t, Settings settings) {
				return getText(t);
			}
		}

	}

	private static class StringRepColumn
			extends AbstractProgramLocationTableColumn<ProgramLocation, StringDataInstance> {

		private StringRepCellRenderer renderer = new StringRepCellRenderer();

		@Override
		public String getColumnName() {
			return "String Representation";
		}

		@Override
		public StringDataInstance getValue(ProgramLocation rowObject, Settings settings,
				Program program, ServiceProvider serviceProvider) throws IllegalArgumentException {
			Data data = DataUtilities.getDataAtLocation(rowObject);
			if (StringDataInstance.isString(data)) {
				StringDataInstance sdi = StringDataInstance.getStringDataInstance(data);
				return sdi;
			}
			return null;
		}

		@Override
		public ProgramLocation getProgramLocation(ProgramLocation rowObject, Settings settings,
				Program program, ServiceProvider serviceProvider) {
			return rowObject;
		}

		@Override
		public GColumnRenderer<StringDataInstance> getColumnRenderer() {
			return renderer;
		}

		private class StringRepCellRenderer extends AbstractGColumnRenderer<StringDataInstance> {

			@Override
			protected String getText(Object value) {
				if (value instanceof StringDataInstance) {
					return ((StringDataInstance) value).getStringRepresentation();
				}
				return "";
			}

			@Override
			public String getFilterString(StringDataInstance t, Settings settings) {
				return getText(t);
			}
		}
	}

	// data type to string column
	private static class DataTypeColumn
			extends AbstractProgramLocationTableColumn<ProgramLocation, String> {

		@Override
		public String getColumnName() {
			return "Data Type";
		}

		@Override
		public String getValue(ProgramLocation rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			Data data = DataUtilities.getDataAtLocation(rowObject);
			if (data == null) {
				return "";
			}
			return (data.getDataType() instanceof AbstractStringDataType)
					? data.getDataType().getMnemonic(settings)
					: data.getDataType().getName();
		}

		@Override
		public ProgramLocation getProgramLocation(ProgramLocation rowObject, Settings settings,
				Program program, ServiceProvider serviceProvider) {
			return rowObject;
		}

	}

	private static class IsAsciiColumn
			extends AbstractProgramLocationTableColumn<ProgramLocation, Boolean> {

		@Override
		public String getColumnName() {
			return "Is Ascii";
		}

		@Override
		public Boolean getValue(ProgramLocation rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {

			Data data = DataUtilities.getDataAtLocation(rowObject);
			String s = StringDataInstance.getStringDataInstance(data).getStringValue();

			return (s != null) &&
				s.codePoints().allMatch(codePoint -> 0 <= codePoint && codePoint < 0x80);
		}

		@Override
		public ProgramLocation getProgramLocation(ProgramLocation rowObject, Settings settings,
				Program program, ServiceProvider serviceProvider) {
			return rowObject;
		}

	}

	private static class HasEncodingErrorColumn
			extends AbstractProgramLocationTableColumn<ProgramLocation, Boolean> {

		@Override
		public String getColumnName() {
			return "Has Encoding Error";
		}

		@Override
		public Boolean getValue(ProgramLocation rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {

			Data data = DataUtilities.getDataAtLocation(rowObject);
			String s = StringDataInstance.getStringDataInstance(data).getStringValue();

			return (s != null) && s.chars().anyMatch(
				codePoint -> codePoint == StringUtilities.UNICODE_REPLACEMENT);
		}

		@Override
		public ProgramLocation getProgramLocation(ProgramLocation rowObject, Settings settings,
				Program program, ServiceProvider serviceProvider) {
			return rowObject;
		}

	}

	private static class CharsetColumn
			extends AbstractProgramLocationTableColumn<ProgramLocation, String> {

		@Override
		public String getColumnName() {
			return "Charset";
		}

		@Override
		public String getValue(ProgramLocation rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {

			Data data = DataUtilities.getDataAtLocation(rowObject);
			return StringDataInstance.getStringDataInstance(data).getCharsetName();
		}

		@Override
		public ProgramLocation getProgramLocation(ProgramLocation rowObject, Settings settings,
				Program program, ServiceProvider serviceProvider) {
			return rowObject;
		}

	}

}
