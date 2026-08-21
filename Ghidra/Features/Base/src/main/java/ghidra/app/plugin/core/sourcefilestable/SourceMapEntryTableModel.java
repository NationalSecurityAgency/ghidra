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
package ghidra.app.plugin.core.sourcefilestable;

import java.util.*;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.database.sourcemap.SourceFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.model.sourcemap.SourceFileManager;
import ghidra.program.model.sourcemap.SourceMapEntry;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.datastruct.Counter;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.GhidraProgramTableModel;
import ghidra.util.task.TaskMonitor;

/**
 * A table model for displaying all the {@link SourceMapEntry}s for a given {@link SourceFile}.
 */
public class SourceMapEntryTableModel extends GhidraProgramTableModel<SourceMapEntryRowObject> {
	private SourceFile sourceFile;
	private static final int END_ADDRESS_INDEX = 2;
	private SourceFileManager sourceManager;

	/**
	 * Constructor.
	 * @param serviceProvider service provider
	 * @param program program
	 * @param monitor task monitor
	 * @param sourceFile source file
	 */
	protected SourceMapEntryTableModel(ServiceProvider serviceProvider, Program program,
			TaskMonitor monitor, SourceFile sourceFile) {
		super("SourceMapEntryTableModel", serviceProvider, program, monitor);
		this.sourceFile = sourceFile;
		this.sourceManager = program.getSourceFileManager();
	}

	@Override
	public ProgramLocation getProgramLocation(int modelRow, int modelColumn) {
		SourceMapEntryRowObject rowObject = getRowObject(modelRow);
		if (modelColumn == END_ADDRESS_INDEX) {
			return new ProgramLocation(program, getEndAddress(rowObject));
		}
		return new ProgramLocation(program, rowObject.getBaseAddress());
	}

	@Override
	public ProgramSelection getProgramSelection(int[] modelRows) {
		AddressSet selection = new AddressSet();
		for (SourceMapEntryRowObject rowObject : getRowObjects(modelRows)) {
			selection.addRange(rowObject.getBaseAddress(), getEndAddress(rowObject));
		}
		return new ProgramSelection(selection);
	}

	@Override
	public void refresh() {
		// this class is used by the TableServicePlugin, which calls refresh on a ProgramChangeEvent
		// we want to check for new SourceMapEntries on such events, so we reload first
		reload();
		super.refresh();
	}

	@Override
	protected void doLoad(Accumulator<SourceMapEntryRowObject> accumulator, TaskMonitor monitor)
			throws CancelledException {
		List<SourceMapEntry> mapEntries = sourceManager.getSourceMapEntries(sourceFile);
		Map<Integer, Counter> lineCount = new HashMap<>();
		for (SourceMapEntry entry : mapEntries) {
			Integer lineNumber = entry.getLineNumber();
			Counter count = lineCount.getOrDefault(lineNumber, new Counter());
			count.increment();
			lineCount.put(lineNumber, count);
		}
		for (SourceMapEntry entry : mapEntries) {
			int lineNumber = entry.getLineNumber();
			SourceMapEntryRowObject rowObject = new SourceMapEntryRowObject(entry.getBaseAddress(),
				lineNumber, entry.getLength(), lineCount.get(lineNumber).intValue());
			accumulator.add(rowObject);
		}
	}

	@Override
	protected TableColumnDescriptor<SourceMapEntryRowObject> createTableColumnDescriptor() {
		TableColumnDescriptor<SourceMapEntryRowObject> descriptor = new TableColumnDescriptor<>();
		descriptor.addVisibleColumn(new BaseAddressTableColumn());
		descriptor.addVisibleColumn(new EndAddressTableColumn());
		descriptor.addVisibleColumn(new LineNumberTableColumn());
		descriptor.addVisibleColumn(new LengthTableColumn());
		descriptor.addVisibleColumn(new CountTableColumn());

		return descriptor;
	}

	private Address getEndAddress(SourceMapEntryRowObject rowObject) {
		long length = rowObject.getLength();
		Address baseAddress = rowObject.getBaseAddress();
		if (length == 0) {
			return rowObject.getBaseAddress();
		}
		return baseAddress.add(length - 1);
	}

	private class BaseAddressTableColumn
			extends AbstractDynamicTableColumn<SourceMapEntryRowObject, Address, Object> {

		@Override
		public String getColumnName() {
			return "Base Address";
		}

		@Override
		public Address getValue(SourceMapEntryRowObject rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.getBaseAddress();
		}
	}

	private class EndAddressTableColumn
			extends AbstractDynamicTableColumn<SourceMapEntryRowObject, Address, Object> {

		@Override
		public String getColumnName() {
			return "End Address";
		}

		@Override
		public Address getValue(SourceMapEntryRowObject rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return getEndAddress(rowObject);
		}
	}

	private class LengthTableColumn
			extends AbstractDynamicTableColumn<SourceMapEntryRowObject, Long, Object> {

		@Override
		public String getColumnName() {
			return "Length";
		}

		@Override
		public Long getValue(SourceMapEntryRowObject rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.getLength();
		}
	}

	private class LineNumberTableColumn
			extends AbstractDynamicTableColumn<SourceMapEntryRowObject, Integer, Object> {

		@Override
		public String getColumnName() {
			return "Line Number";
		}

		@Override
		public Integer getValue(SourceMapEntryRowObject rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.getLineNumber();
		}
	}

	private class CountTableColumn
			extends AbstractDynamicTableColumn<SourceMapEntryRowObject, Integer, Object> {

		@Override
		public String getColumnName() {
			return "Count";
		}

		@Override
		public Integer getValue(SourceMapEntryRowObject rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.getCount();
		}
	}

}
