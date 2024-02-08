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
package ghidra.app.plugin.core.codebrowser;

import java.util.stream.StreamSupport;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.GhidraProgramTableModel;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link GhidraProgramTableModel} for displaying tables in which one row corresponds
 * to an {@link AddressRange}
 */
public class AddressRangeTableModel extends GhidraProgramTableModel<AddressRangeInfo> {

	private ProgramSelection selection;
	private static final int MAX_ADDRESS_COLUMN_INDEX = 1;
	private int resultsLimit;
	private long minLength;

	protected AddressRangeTableModel(PluginTool tool, Program program, ProgramSelection selection,
			int resultsLimit, long minLength) {
		super("Selected Ranges in " + program.getName(), tool, program, null);
		this.selection = selection;
		this.resultsLimit = resultsLimit;
		this.minLength = minLength;
	}

	@Override
	public ProgramLocation getProgramLocation(int modelRow, int modelColumn) {
		AddressRangeInfo rangeInfo = getRowObject(modelRow);
		if (modelColumn == MAX_ADDRESS_COLUMN_INDEX) {
			return new ProgramLocation(program, rangeInfo.max());
		}
		return new ProgramLocation(program, rangeInfo.min());
	}

	@Override
	public ProgramSelection getProgramSelection(int[] modelRows) {
		AddressSet ranges = new AddressSet();
		for (AddressRangeInfo rangeInfo : getRowObjects(modelRows)) {
			ranges.addRange(program, rangeInfo.min(), rangeInfo.max());
		}
		return new ProgramSelection(program.getAddressFactory(), ranges);
	}

	@Override
	protected void doLoad(Accumulator<AddressRangeInfo> accumulator, TaskMonitor monitor)
			throws CancelledException {
		AddressRangeIterator rangeIter = selection.getAddressRanges();
		ReferenceManager refManager = program.getReferenceManager();
		while (rangeIter.hasNext()) {
			monitor.checkCancelled();
			AddressRange range = rangeIter.next();
			if (range.getLength() < minLength) {
				continue;
			}
			boolean isSameByte = AddressRangeInfo.isSameByteValue(range.getMinAddress(),
				range.getMaxAddress(), program);

			AddressSet rangeSet = new AddressSet(range);

			AddressIterator destAddrIter =
				refManager.getReferenceDestinationIterator(rangeSet, true);
			int numRefsTo = StreamSupport.stream(destAddrIter.spliterator(), false)
					.map(addr -> refManager.getReferenceCountTo(addr))
					.reduce(0, Integer::sum);

			AddressIterator srcAddrIter =
				refManager.getReferenceSourceIterator(rangeSet, true);
			int numRefsFrom = StreamSupport.stream(srcAddrIter.spliterator(), false)
					.map(addr -> refManager.getReferenceCountFrom(addr))
					.reduce(0, Integer::sum);

			AddressRangeInfo info = new AddressRangeInfo(range.getMinAddress(),
				range.getMaxAddress(), range.getLength(), isSameByte, numRefsTo, numRefsFrom);

			accumulator.add(info);
			if (accumulator.size() >= resultsLimit) {
				Msg.showWarn(this, null, "Results Truncated",
					"Results are limited to " + resultsLimit + " address ranges.\n" +
						"This limit can be changed by the tool option \"" +
						CodeBrowserSelectionPlugin.OPTION_CATEGORY_NAME + " -> " +
						CodeBrowserSelectionPlugin.RANGES_LIMIT_OPTION_NAME + "\".");
				break;
			}
		}
		if (accumulator.isEmpty()) {
			Msg.showWarn(this, null, "No Ranges to Display",
				"No ranges to display - consider adjusting \"" +
					CodeBrowserSelectionPlugin.OPTION_CATEGORY_NAME + " -> " +
					CodeBrowserSelectionPlugin.MIN_RANGE_SIZE_OPTION_NAME + "\".");
		}
	}

	@Override
	public void refresh() {
		reload();
	}

	@Override
	protected TableColumnDescriptor<AddressRangeInfo> createTableColumnDescriptor() {
		TableColumnDescriptor<AddressRangeInfo> descriptor = new TableColumnDescriptor<>();
		descriptor.addVisibleColumn(new MinAddressTableColumn());
		descriptor.addVisibleColumn(new MaxAddressTableColumn());
		descriptor.addVisibleColumn(new LengthTableColumn());
		descriptor.addVisibleColumn(new IdenticalBytesTableColumn());
		descriptor.addVisibleColumn(new NumRefsToTableColumn());
		descriptor.addVisibleColumn(new NumRefsFromTableColumn());
		descriptor.addVisibleColumn(new BlockNameTableColumn());
		descriptor.addHiddenColumn(new AddressRangeBytesTableColumn());
		descriptor.addHiddenColumn(new AddressRangeCodeUnitTableColumn());

		return descriptor;
	}

	private class MinAddressTableColumn
			extends AbstractDynamicTableColumn<AddressRangeInfo, Address, Object> {

		@Override
		public String getColumnName() {
			return "Min Address";
		}

		@Override
		public Address getValue(AddressRangeInfo rangeInfo, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rangeInfo.min();
		}
	}

	private class MaxAddressTableColumn
			extends AbstractDynamicTableColumn<AddressRangeInfo, Address, Object> {

		@Override
		public String getColumnName() {
			return "Max Address";
		}

		@Override
		public Address getValue(AddressRangeInfo rangeInfo, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rangeInfo.max();
		}
	}

	private class LengthTableColumn
			extends AbstractDynamicTableColumn<AddressRangeInfo, Long, Object> {

		@Override
		public String getColumnName() {
			return "Length";
		}

		@Override
		public Long getValue(AddressRangeInfo rangeInfo, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rangeInfo.size();
		}
	}

	private class IdenticalBytesTableColumn
			extends AbstractDynamicTableColumn<AddressRangeInfo, Boolean, Object> {

		@Override
		public String getColumnName() {
			return "Identical Bytes";
		}

		@Override
		public String getColumnDescription() {
			return "Do all bytes in the range have the same value";
		}

		@Override
		public Boolean getValue(AddressRangeInfo rangeInfo, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rangeInfo.isSameByte();
		}
	}

	private class BlockNameTableColumn
			extends AbstractDynamicTableColumn<AddressRangeInfo, String, Object> {

		@Override
		public String getColumnName() {
			return "Block Name";
		}

		@Override
		public String getValue(AddressRangeInfo rangeInfo, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return program.getMemory().getBlock(rangeInfo.min()).getName();
		}
	}

	private class NumRefsToTableColumn
			extends AbstractDynamicTableColumn<AddressRangeInfo, Integer, Object> {

		@Override
		public String getColumnName() {
			return "To References";
		}

		@Override
		public Integer getValue(AddressRangeInfo rangeInfo, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rangeInfo.numRefsTo();
		}
	}

		private class NumRefsFromTableColumn
				extends AbstractDynamicTableColumn<AddressRangeInfo, Integer, Object> {

			@Override
			public String getColumnName() {
				return "From References";
			}

			@Override
			public Integer getValue(AddressRangeInfo rangeInfo, Settings settings, Object data,
					ServiceProvider services) throws IllegalArgumentException {
				return rangeInfo.numRefsFrom();
			}
		}


}
