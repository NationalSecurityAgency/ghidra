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

import docking.widgets.table.*;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.TestDummyServiceProvider;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class TestDataKeyModel extends ThreadedTableModelStub<Long> {

	final static int ROWCOUNT = 12;

	public final static int BYTE_COL = 0;
	public final static int SHORT_COL = 1;
	public final static int INT_COL = 2;
	public final static int LONG_COL = 3;
	public final static int FLOAT_COL = 4;
	public final static int DOUBLE_COL = 5;
	public final static int STRING_COL = 6;

	private Byte[] bytes = new Byte[] { new Byte((byte) 0x09), new Byte((byte) 0x03),
		new Byte((byte) 0x0c), new Byte((byte) 0x55), new Byte((byte) 0x00), new Byte((byte) 0xdf),
		new Byte((byte) 0xff), new Byte((byte) 0x03), new Byte((byte) 0x16), new Byte((byte) 0x02),
		new Byte((byte) 0x03), new Byte((byte) 0x04), };

	private Short[] shorts = new Short[] { new Short((short) 0x0841), new Short((short) 0xb0f7),
		new Short((short) 0xf130), new Short((short) 0x84e3), new Short((short) 0x2976),
		new Short((short) 0x17d9), new Short((short) 0xf146), new Short((short) 0xc4a5),
		new Short((short) 0x88f1), new Short((short) 0x966d), new Short((short) 0x966e),
		new Short((short) 0x966f), };

	private Integer[] ints =
		new Integer[] { new Integer(0x039D492B), new Integer(0x0A161497), new Integer(0x06AA1497),
			new Integer(0x0229EE9E), new Integer(0xFB7428E1), new Integer(0xD2B4ED2F),
			new Integer(0x0C1F67DE), new Integer(0x0E61C987), new Integer(0x0133751F),
			new Integer(0x07B39541), new Integer(0x07B39542), new Integer(0x07B39542), };

	private Long[] longs = new Long[] { new Long(0x0000000DFAA00C4FL),
		new Long(0x00000001FD7CA6A6L), new Long(0xFFFFFFF4D0EB4AB8L), new Long(0x0000000445246143L),
		new Long(0xFFFFFFF5696F1780L), new Long(0x0000000685526E5DL), new Long(0x00000009A1FD98EEL),
		new Long(0x00000004AD2B1869L), new Long(0x00000002928E64C8L), new Long(0x000000071CE1DDB2L),
		new Long(0x000000071CE1DDB3L), new Long(0x000000071CE1DDB4L), };

	private Float[] floats =
		new Float[] { new Float((float) 0.143111240), new Float((float) 0.084097680),
			new Float((float) 0.551214800), new Float((float) 0.310384800),
			new Float((float) 0.738005640), new Float((float) 0.913325130),
			new Float((float) 0.016024105), new Float((float) 0.233800740),
			new Float((float) 0.092682876), new Float((float) 0.952251900),
			new Float((float) 0.952251901), new Float((float) 0.952251902), };

	private Double[] doubles =
		new Double[] { new Double(0.50554326393620910), new Double(0.13198657566384920),
			new Double(0.64075103656548560), new Double(0.02537676611361095),
			new Double(0.90734608401968010), new Double(0.28502871389575400),
			new Double(0.13398664627861856), new Double(0.12874345736088588),
			new Double(0.40378684558854416), new Double(0.77268978814256020),
			new Double(0.77268978814256021), new Double(0.77268978814256022), };

	protected String[] strings = new String[] { "one", "two", "THREE", "Four", "FiVe", "sIx",
		"SeVEn", "EighT", "NINE", "ten", "ten", "ten" };

	private long timeBetweenAddingDataItemsInMillis = 1;

	private volatile IncrementalLoadJob<Long> loadJob = null;

	TestDataKeyModel() {
		this(null, false);
	}

	TestDataKeyModel(TaskMonitor monitor, boolean loadIncrementally) {
		super("Test Data Key Model", new TestDummyServiceProvider(), monitor, loadIncrementally);
		setDefaultTableSortState(TableSortState.createDefaultSortState(LONG_COL));
	}

	@Override
	protected IncrementalLoadJob<Long> createIncrementalLoadJob() {
		loadJob = new IncrementalLoadJob<>(this, new IncrementalLoadJobListener());
		return loadJob;
	}

	IncrementalLoadJob<Long> getCurrentLoadJob() {
		return loadJob;
	}

	void setDelayTimeBetweenAddingDataItemsWhileLoading(long millis) {
		this.timeBetweenAddingDataItemsInMillis = millis;
	}

	long getDelayTimeBetweenAddingDataItemsWhileLoading() {
		return timeBetweenAddingDataItemsInMillis;
	}

	int getTestRowCount() {
		return ROWCOUNT;
	}

	@Override
	protected void doLoad(Accumulator<Long> accumulator, TaskMonitor monitor)
			throws CancelledException {
		for (int i = 0; i < ROWCOUNT; i++) {
			monitor.checkCanceled();
			accumulator.add((long) i);
			sleep(timeBetweenAddingDataItemsInMillis);
		}
	}

	private void sleep(long millis) {
		try {
			Thread.sleep(millis);
		}
		catch (InterruptedException e) {
			// just a test--do we care?
		}
	}

	@Override
	protected TableColumnDescriptor<Long> createTableColumnDescriptor() {
		TableColumnDescriptor<Long> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(new ByteTableColumn());
		descriptor.addVisibleColumn(new ShortTableColumn());
		descriptor.addVisibleColumn(new IntegerTableColumn());
		descriptor.addVisibleColumn(new LongTableColumn());
		descriptor.addVisibleColumn(new FloatTableColumn());
		descriptor.addVisibleColumn(new DoubleTableColumn());
		descriptor.addVisibleColumn(new StringTableColumn());

		return descriptor;
	}

	private class ByteTableColumn extends AbstractDynamicTableColumnStub<Long, Byte> {

		@Override
		public String getColumnName() {
			return "Byte";
		}

		@Override
		public Byte getValue(Long rowObject, Settings settings, ServiceProvider provider)
				throws IllegalArgumentException {
			int longAsInt = rowObject.intValue();
			if (longAsInt < 0 || longAsInt >= bytes.length) {
				// must be using a model that adds more data than the default; fabricate a result
				return (byte) System.currentTimeMillis();
			}
			return bytes[rowObject.intValue()];
		}
	}

	private class ShortTableColumn extends AbstractDynamicTableColumnStub<Long, Short> {

		@Override
		public String getColumnName() {
			return "Short";
		}

		@Override
		public Short getValue(Long rowObject, Settings settings, ServiceProvider provider)
				throws IllegalArgumentException {
			int longAsInt = rowObject.intValue();
			if (longAsInt < 0 || longAsInt >= shorts.length) {
				// must be using a model that adds more data than the default; fabricate a result
				return (short) System.currentTimeMillis();
			}
			return shorts[rowObject.intValue()];
		}
	}

	private class IntegerTableColumn extends AbstractDynamicTableColumnStub<Long, Integer> {

		@Override
		public String getColumnName() {
			return "Integer";
		}

		@Override
		public Integer getValue(Long rowObject, Settings settings, ServiceProvider provider)
				throws IllegalArgumentException {
			int longAsInt = rowObject.intValue();
			if (longAsInt < 0 || longAsInt >= ints.length) {
				// must be using a model that adds more data than the default; fabricate a result
				return (int) System.currentTimeMillis();
			}
			return ints[rowObject.intValue()];
		}
	}

	private class LongTableColumn extends AbstractDynamicTableColumnStub<Long, Long> {

		@Override
		public String getColumnName() {
			return "Long";
		}

		@Override
		public Long getValue(Long rowObject, Settings settings, ServiceProvider provider)
				throws IllegalArgumentException {
			int longAsInt = rowObject.intValue();
			if (longAsInt < 0 || longAsInt >= longs.length) {
				// must be using a model that adds more data than the default; fabricate a result
				return System.currentTimeMillis();
			}
			return longs[longAsInt];
		}
	}

	private class FloatTableColumn extends AbstractDynamicTableColumnStub<Long, Float> {

		@Override
		public String getColumnName() {
			return "Float";
		}

		@Override
		public Float getValue(Long rowObject, Settings settings, ServiceProvider provider)
				throws IllegalArgumentException {
			int longAsInt = rowObject.intValue();
			if (longAsInt < 0 || longAsInt >= floats.length) {
				// must be using a model that adds more data than the default; fabricate a result
				return (float) System.currentTimeMillis();
			}
			return floats[rowObject.intValue()];
		}
	}

	private class DoubleTableColumn extends AbstractDynamicTableColumnStub<Long, Double> {

		@Override
		public String getColumnName() {
			return "Double";
		}

		@Override
		public Double getValue(Long rowObject, Settings settings, ServiceProvider provider)
				throws IllegalArgumentException {
			int longAsInt = rowObject.intValue();
			if (longAsInt < 0 || longAsInt >= doubles.length) {
				// must be using a model that adds more data than the default; fabricate a result
				return (double) System.currentTimeMillis();
			}
			return doubles[rowObject.intValue()];
		}
	}

	private class StringTableColumn extends AbstractDynamicTableColumnStub<Long, String> {

		@Override
		public String getColumnName() {
			return "String";
		}

		@Override
		public String getValue(Long rowObject, Settings settings, ServiceProvider provider)
				throws IllegalArgumentException {
			int longAsInt = rowObject.intValue();
			if (longAsInt < 0 || longAsInt >= strings.length) {
				// must be using a model that adds more data than the default; fabricate a result
				return Long.toString(System.currentTimeMillis());
			}
			return strings[rowObject.intValue()];
		}
	}
}
