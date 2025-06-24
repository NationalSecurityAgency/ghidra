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
package docking.widgets.table.threaded;

import java.util.List;

import docking.widgets.table.AbstractDynamicTableColumnStub;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.TestDummyServiceProvider;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class TestThreadedTableModel extends ThreadedTableModelStub<TestRowObject> {

	// note: this data is derived from TestDataKeyModel, but can be changed
	private List<TestRowObject> startData = List.of(
		new TestRowObject("one", 0x0000000DFAA00C4FL),
		new TestRowObject("two", 0x00000001FD7CA6A6L),
		new TestRowObject("THREE", 0xFFFFFFF4D0EB4AB8L),
		new TestRowObject("Four", 0x0000000445246143L),
		new TestRowObject("FiVe", 0xFFFFFFF5696F1780L),
		new TestRowObject("sIx", 0x0000000685526E5DL),
		new TestRowObject("SeVEn", 0x00000009A1FD98EEL),
		new TestRowObject("EighT", 0x00000004AD2B1869L),
		new TestRowObject("NINE", 0x00000002928E64C8L),
		new TestRowObject("ten", 0x000000071CE1DDB2L),
		new TestRowObject("ten", 0x000000071CE1DDB3L),
		new TestRowObject("ten", 0x000000071CE1DDB4L));

	public TestThreadedTableModel() {
		super("Test Data Key Model", new TestDummyServiceProvider(), null, false);
	}

	public int getStartRowCount() {
		return startData.size();
	}

	@Override
	protected TableColumnDescriptor<TestRowObject> createTableColumnDescriptor() {

		TableColumnDescriptor<TestRowObject> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(new ByteTableColumn());
		descriptor.addVisibleColumn(new LongTableColumn());
		descriptor.addVisibleColumn(new StringTableColumn());

		return descriptor;
	}

	@Override
	protected void doLoad(Accumulator<TestRowObject> accumulator, TaskMonitor monitor)
			throws CancelledException {
		for (TestRowObject element : startData) {
			monitor.checkCancelled();
			accumulator.add(element);
		}
	}

	private class ByteTableColumn extends AbstractDynamicTableColumnStub<TestRowObject, Byte> {

		@Override
		public String getColumnName() {
			return "Byte";
		}

		@Override
		public Byte getValue(TestRowObject rowObject, Settings settings, ServiceProvider provider)
				throws IllegalArgumentException {
			return (byte) rowObject.getLongValue();
		}
	}

	private class LongTableColumn extends AbstractDynamicTableColumnStub<TestRowObject, Long> {

		@Override
		public String getColumnName() {
			return "Long";
		}

		@Override
		public Long getValue(TestRowObject rowObject, Settings settings, ServiceProvider provider)
				throws IllegalArgumentException {
			return rowObject.getLongValue();
		}
	}

	private class StringTableColumn extends AbstractDynamicTableColumnStub<TestRowObject, String> {

		@Override
		public String getColumnName() {
			return "String";
		}

		@Override
		public String getValue(TestRowObject rowObject, Settings settings, ServiceProvider provider)
				throws IllegalArgumentException {
			return rowObject.getStringValue();
		}
	}
}
