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
package ghidra.app.plugin.core.string;

import docking.widgets.table.DiscoverableTableUtils;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.program.util.string.FoundString;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.field.*;
import ghidra.util.task.TaskMonitor;

/**
 * Table model for the Search -&gt; For Strings... result dialog.
 * <p>
 */
public class StringTableModel extends AddressBasedTableModel<FoundString> {

	private volatile StringTableOptions options;

	StringTableModel(PluginTool tool, StringTableOptions options) {
		super("Strings Table", tool, null, null, true);
		this.options = options;

		if (options.getWordModelInitialized()) {
			addTableColumn(new ConfidenceWordTableColumn());
		}
	}

	@Override
	public ProgramSelection getProgramSelection(int[] rows) {

		AddressSet addressSet = new AddressSet();
		for (int row : rows) {
			FoundString foundString = getRowObject(row);
			Address addr = foundString.getAddress();
			if (addr != null) {
				addressSet.addRange(addr, addr.add(foundString.getLength() - 1));
			}
		}
		return new ProgramSelection(addressSet);
	}

	@Override
	public Address getAddress(int row) {
		FoundString stringData = getRowObject(row);
		return stringData.getAddress();
	}

	void setOptions(StringTableOptions options) {
		this.options = options;
	}

	@Override
	protected void doLoad(Accumulator<FoundString> accumulator, TaskMonitor monitor)
			throws CancelledException {

		if (getProgram() == null) {
			return;
		}

		CombinedStringSearcher searcher =
			new CombinedStringSearcher(getProgram(), options, accumulator);

		searcher.search(monitor);
	}

	@Override
	protected TableColumnDescriptor<FoundString> createTableColumnDescriptor() {
		TableColumnDescriptor<FoundString> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(new IsDefinedTableColumn());
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new AddressTableColumn()), 0, true);
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new LabelTableColumn()));
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new CodeUnitTableColumn()));
		descriptor.addVisibleColumn(new StringViewTableColumn());
		descriptor.addVisibleColumn(new StringTypeTableColumn());
		descriptor.addVisibleColumn(new StringLengthTableColumn());

		return descriptor;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	static class StringTypeTableColumn
			extends AbstractProgramBasedDynamicTableColumn<FoundString, String> {
		@Override
		public String getColumnName() {
			return "String Type";
		}

		@Override
		public String getValue(FoundString rowObject, Settings settings, Program program,
				ServiceProvider services) throws IllegalArgumentException {
			// need to add a type column to the table so I can get the datatype out
			return rowObject.getDataType().toString();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}
	}

	static class StringLengthTableColumn
			extends AbstractProgramBasedDynamicTableColumn<FoundString, Integer> {
		@Override
		public String getColumnName() {
			return "Length";
		}

		@Override
		public Integer getValue(FoundString rowObject, Settings settings, Program program,
				ServiceProvider services) throws IllegalArgumentException {

			return rowObject.getStringLength(program.getMemory());
		}

		@Override
		public int getColumnPreferredWidth() {
			return 80;
		}
	}

	static class IsDefinedTableColumn
			extends AbstractProgramBasedDynamicTableColumn<FoundString, FoundString.DefinedState> {
		@Override
		public String getColumnName() {
			return "Defined";
		}

		@Override
		public FoundString.DefinedState getValue(FoundString rowObject, Settings settings,
				Program program, ServiceProvider services) throws IllegalArgumentException {

			return rowObject.getDefinedState();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 40;
		}
	}

	class StringViewTableColumn
			extends AbstractProgramBasedDynamicTableColumn<FoundString, String> {

		@Override
		public String getColumnName() {
			return "String View";
		}

		@Override
		public String getValue(FoundString foundString, Settings settings, Program program,
				ServiceProvider services) throws IllegalArgumentException {

			return (foundString != null && foundString.getLength() > 0)
					? foundString.getDataInstance(
						getProgram().getMemory()).getStringRepresentation()
					: "";
		}
	}

	private class ConfidenceWordTableColumn
			extends AbstractProgramBasedDynamicTableColumn<FoundString, String> {

		@Override
		public String getColumnName() {
			return "Is Word";
		}

		@Override
		public String getColumnDescription() {
			return "Whether the string is a high-confidence word string, according to the '" +
				options.getWordModelFile() + "' model.";
		}

		@Override
		public String getValue(FoundString rowObject, Settings settings, Program p,
				ServiceProvider services) throws IllegalArgumentException {
			// This value will only get shown if the word model is initialized. If initialized,
			// the FoundString will be of the type FoundStringWithWordStatus
			if (rowObject instanceof FoundStringWithWordStatus) {
				return ((Boolean) ((FoundStringWithWordStatus) rowObject).isHighConfidenceWord()).toString();
			}

			// This should not show -- but if it does, it indicates an issue.
			return "N/A - Model Error";
		}
	}

}
