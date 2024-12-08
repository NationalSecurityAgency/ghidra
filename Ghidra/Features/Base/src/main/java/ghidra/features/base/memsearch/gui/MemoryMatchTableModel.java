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
package ghidra.features.base.memsearch.gui;

import java.awt.*;

import docking.widgets.table.*;
import generic.theme.GThemeDefaults.Colors.Tables;
import ghidra.docking.settings.Settings;
import ghidra.features.base.memsearch.format.SearchFormat;
import ghidra.features.base.memsearch.matcher.ByteMatcher;
import ghidra.features.base.memsearch.searcher.MemoryMatch;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.*;
import ghidra.util.HTMLUtilities;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.table.field.*;
import ghidra.util.task.TaskMonitor;

/**
 * Table model for memory search results.
 */
public class MemoryMatchTableModel extends AddressBasedTableModel<MemoryMatch> {
	private Color CHANGED_COLOR = Tables.ERROR_UNSELECTED;
	private Color CHANGED_SELECTED_COLOR = Tables.ERROR_SELECTED;

	private MemoryMatchTableLoader loader;

	MemoryMatchTableModel(ServiceProvider serviceProvider, Program program) {
		super("Memory Search", serviceProvider, program, null, true);
	}

	@Override
	protected TableColumnDescriptor<MemoryMatch> createTableColumnDescriptor() {
		TableColumnDescriptor<MemoryMatch> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new AddressTableColumn()), 1, true);
		descriptor.addVisibleColumn(new MatchBytesColumn());
		descriptor.addVisibleColumn(new MatchValueColumn());
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new LabelTableColumn()));
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new CodeUnitTableColumn()));

		return descriptor;
	}

	@Override
	protected void doLoad(Accumulator<MemoryMatch> accumulator, TaskMonitor monitor)
			throws CancelledException {
		if (loader == null) {
			return;
		}
		loader.loadResults(accumulator, monitor);
		loader = null;
	}

	void setLoader(MemoryMatchTableLoader loader) {
		this.loader = loader;
		reload();
	}

	public boolean isSortedOnAddress() {
		TableSortState sortState = getTableSortState();
		if (sortState.isUnsorted()) {
			return false;
		}

		ColumnSortState primaryState = sortState.getAllSortStates().get(0);
		DynamicTableColumn<MemoryMatch, ?, ?> column =
			getColumn(primaryState.getColumnModelIndex());
		String name = column.getColumnName();
		if (AddressTableColumn.NAME.equals(name)) {
			return true;
		}
		return false;
	}

	@Override
	public ProgramLocation getProgramLocation(int modelRow, int modelColumn) {
		Program p = getProgram();
		if (p == null) {
			return null; // we've been disposed
		}

		DynamicTableColumn<MemoryMatch, ?, ?> column = getColumn(modelColumn);
		Class<?> columnClass = column.getClass();
		if (column instanceof MappedTableColumn mappedColumn) {
			columnClass = mappedColumn.getMappedColumnClass();
		}
		if (columnClass == AddressTableColumn.class || columnClass == MatchBytesColumn.class ||
			columnClass == MatchValueColumn.class) {
			return new BytesFieldLocation(p, getAddress(modelRow));
		}

		return super.getProgramLocation(modelRow, modelColumn);
	}

	@Override
	public Address getAddress(int row) {
		MemoryMatch result = getRowObject(row);
		return result.getAddress();
	}

	@Override
	public ProgramSelection getProgramSelection(int[] rows) {
		AddressSet addressSet = new AddressSet();
		for (int row : rows) {
			MemoryMatch result = getRowObject(row);
			int addOn = result.getLength() - 1;
			Address minAddr = getAddress(row);
			Address maxAddr = minAddr;
			try {
				maxAddr = minAddr.addNoWrap(addOn);
				addressSet.addRange(minAddr, maxAddr);
			}
			catch (AddressOverflowException e) {
				// I guess we don't care--not sure why this is undocumented :(
			}
		}
		return new ProgramSelection(addressSet);
	}

	public class MatchBytesColumn
			extends DynamicTableColumnExtensionPoint<MemoryMatch, String, Program> {

		private ByteArrayRenderer renderer = new ByteArrayRenderer();

		@Override
		public String getColumnName() {
			return "Match Bytes";
		}

		@Override
		public String getValue(MemoryMatch match, Settings settings, Program pgm,
				ServiceProvider service) throws IllegalArgumentException {

			return getByteString(match.getBytes());
		}

		private String getByteString(byte[] bytes) {
			StringBuilder b = new StringBuilder();
			int max = bytes.length - 1;
			for (int i = 0;; i++) {
				b.append(String.format("%02x", bytes[i]));
				if (i == max) {
					break;
				}
				b.append(" ");
			}
			return b.toString();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 200;
		}

		@Override
		public GColumnRenderer<String> getColumnRenderer() {
			return renderer;
		}
	}

	public class MatchValueColumn
			extends DynamicTableColumnExtensionPoint<MemoryMatch, String, Program> {

		private ValueRenderer renderer = new ValueRenderer();

		@Override
		public String getColumnName() {
			return "Match Value";
		}

		@Override
		public String getValue(MemoryMatch match, Settings settings, Program pgm,
				ServiceProvider service) throws IllegalArgumentException {

			ByteMatcher byteMatcher = match.getByteMatcher();
			SearchSettings searchSettings = byteMatcher.getSettings();
			SearchFormat format = searchSettings.getSearchFormat();
			return format.getValueString(match.getBytes(), searchSettings);
		}

		@Override
		public int getColumnPreferredWidth() {
			return 200;
		}

		@Override
		public GColumnRenderer<String> getColumnRenderer() {
			return renderer;
		}
	}

	private class ByteArrayRenderer extends AbstractGColumnRenderer<String> {
		public ByteArrayRenderer() {
			setHTMLRenderingEnabled(true);
		}

		@Override
		protected Font getDefaultFont() {
			return fixedWidthFont;
		}

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {
			super.getTableCellRendererComponent(data);
			MemoryMatch match = (MemoryMatch) data.getRowObject();
			String text = data.getValue().toString();
			if (match.isChanged()) {
				text = getHtmlColoredString(match, data.isSelected());
			}
			setText(text);
			return this;
		}

		private String getHtmlColoredString(MemoryMatch match, boolean isSelected) {
			Color color = isSelected ? Tables.ERROR_SELECTED : Tables.ERROR_UNSELECTED;

			StringBuilder b = new StringBuilder();
			b.append("<HTML>");
			byte[] bytes = match.getBytes();
			byte[] previousBytes = match.getPreviousBytes();
			int max = bytes.length - 1;
			for (int i = 0;; i++) {
				String byteString = String.format("%02x", bytes[i]);
				if (bytes[i] != previousBytes[i]) {
					byteString = HTMLUtilities.colorString(color, byteString);
				}
				b.append(byteString);
				if (i == max)
					break;
				b.append(" ");
			}

			return b.toString();
		}

		@Override
		public String getFilterString(String t, Settings settings) {
			// This returns the formatted string without the formatted markup
			return t;
		}
	}

	private class ValueRenderer extends AbstractGColumnRenderer<String> {

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {
			super.getTableCellRendererComponent(data);
			setText((String) data.getValue());

			MemoryMatch match = (MemoryMatch) data.getRowObject();
			if (match.isChanged()) {
				setForeground(data.isSelected() ? CHANGED_SELECTED_COLOR : CHANGED_COLOR);
			}
			return this;
		}

		@Override
		public String getFilterString(String t, Settings settings) {
			return t;
		}
	}

}
