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
package ghidra.app.plugin.core.scalartable;

import java.awt.Component;
import java.math.BigInteger;
import java.util.Comparator;

import javax.swing.*;
import javax.swing.table.TableModel;

import docking.widgets.table.*;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.*;
import ghidra.program.model.data.Resource;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.datastruct.SizeLimitedAccumulatorWrapper;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.table.field.*;
import ghidra.util.task.TaskMonitor;

/**
 * Model that backs the table associated with the {@link ScalarSearchProvider}
 */
public class ScalarSearchModel extends AddressBasedTableModel<ScalarRowObject> {

	static final int PREVIEW_COLUMN = 1;
	static final int HEX_COLUMN = 2;

	static final int TEMP_MAX_RESULTS = 1_000_000;

	private Listing listing;

	private ProgramSelection currentSelection;
	private long minValue;
	private long maxValue;

	private SizeLimitedAccumulatorWrapper<ScalarRowObject> sizedAccumulator;

	ScalarSearchModel(ScalarSearchPlugin plugin, ProgramSelection currentSelection) {
		super("Scalars", plugin.getTool(), null, null);
		this.currentSelection = currentSelection;
	}

	@Override
	protected TableColumnDescriptor<ScalarRowObject> createTableColumnDescriptor() {

		TableColumnDescriptor<ScalarRowObject> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new AddressTableColumn()), 1, true);
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new PreviewTableColumn()));
		descriptor.addVisibleColumn(new ScalarHexUnsignedValueTableColumn());
		descriptor.addVisibleColumn(new ScalarSignedDecimalValueTableColumn());
		descriptor.addHiddenColumn(new ScalarUnsignedDecimalValueTableColumn());
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new ScalarFunctionNameTableColumn()));
		descriptor.addHiddenColumn(new ScalarBitCountTableColumn());
		descriptor.addHiddenColumn(new ScalarSignednessTableColumn());
		return descriptor;
	}

	@Override
	protected void doLoad(Accumulator<ScalarRowObject> accumulator, TaskMonitor monitor)
			throws CancelledException {

		if (listing == null) {
			return;
		}

		sizedAccumulator = new SizeLimitedAccumulatorWrapper<>(accumulator, TEMP_MAX_RESULTS);

		if (currentSelection != null) {
			loadTableFromSelection(monitor);
			return;
		}

		monitor.initialize(listing.getNumCodeUnits());
		InstructionIterator instructions = listing.getInstructions(true);
		DataIterator dataIterator = listing.getDefinedData(true);

		iterateOverInstructions(monitor, instructions);
		iterateOverData(monitor, dataIterator);

		sizedAccumulator = null;
	}

	private boolean tooManyResults() {
		return sizedAccumulator.hasReachedSizeLimit();
	}

	void initialize(Program p, long newMinValue, long newMaxValue) {
		this.minValue = newMinValue;
		this.maxValue = newMaxValue;
		setProgram(p);
		listing = p.getListing();
		reload();
	}

	private void loadTableFromSelection(TaskMonitor monitor) throws CancelledException {

		BigInteger max = BigInteger.valueOf(0);

		AddressRangeIterator ranges = currentSelection.getAddressRanges();
		for (AddressRange range : ranges) {
			max = max.add(range.getBigLength());
		}

		monitor.initialize(max.longValue());

		ranges = currentSelection.getAddressRanges();
		for (AddressRange range : ranges) {

			AddressSet addressSet = new AddressSet(range.getMinAddress(), range.getMaxAddress());

			InstructionIterator instructions = listing.getInstructions(addressSet, true);
			iterateOverInstructions(monitor, instructions);

			DataIterator dataIterator = listing.getDefinedData(addressSet, true);
			iterateOverData(monitor, dataIterator);
		}
	}

	private void iterateOverInstructions(TaskMonitor monitor, InstructionIterator instructions)
			throws CancelledException {

		for (Instruction instruction : instructions) {

			monitor.checkCanceled();
			monitor.incrementProgress(1);

			if (tooManyResults()) {
				return;
			}

			int numOperands = instruction.getNumOperands();

			for (int opIndex = 0; opIndex <= numOperands; opIndex++) {

				monitor.checkCanceled();

				Object[] opObjs = instruction.getOpObjects(opIndex);
				Reference[] operandReferences = instruction.getOperandReferences(opIndex);

				if (operandReferences.length == 0) {
					getScalarsFromInstruction(instruction, opObjs, monitor);
				}
			}
		}
	}

	private void iterateOverData(TaskMonitor monitor, DataIterator dataIterator)
			throws CancelledException {

		while (dataIterator.hasNext()) {

			monitor.checkCanceled();
			monitor.incrementProgress(1);

			if (tooManyResults()) {
				return;
			}

			Data data = dataIterator.next();

			int numComponents = data.getNumComponents();

			if (numComponents > 0) {
				findScalarsInCompositeData(data, numComponents, monitor);
			}
			else {
				addScalarFromData(data);
			}
		}
	}

	private void getScalarsFromInstruction(Instruction instruction, Object[] opObjs,
			TaskMonitor monitor) throws CancelledException {

		for (Object opObj : opObjs) {
			monitor.checkCanceled();

			Scalar scalar = getScalarFromOperand(opObj, monitor);
			if (scalar != null) {
				addMatch(new ScalarRowObject(instruction, scalar));
			}
		}
	}

	private void addMatch(ScalarRowObject rowObject) {

		if (rowObject == null) {
			return;
		}

		Scalar scalar = rowObject.getScalar();
		long value = scalar.isSigned() ? scalar.getSignedValue() : scalar.getUnsignedValue();
		if ((value < minValue) || (value > maxValue)) {
			return;
		}

		sizedAccumulator.add(rowObject);
	}

	private void findScalarsInCompositeData(Data data, int numComponents, TaskMonitor monitor)
			throws CancelledException {

		if (data.getDataType() instanceof Resource) {
			return;
		}

		for (int i = 0; i < numComponents; i++) {

			monitor.checkCanceled();
			Data component = data.getComponent(i);
			getScalarsFromCompositeData(data, component, monitor);
		}
	}

	private void getScalarsFromCompositeData(Data data, Data component, TaskMonitor monitor)
			throws CancelledException {

		int numSubComponents = component.getNumComponents();
		if (numSubComponents == 0) {
			addDataFromComponent(data, component);
			return;
		}

		for (int i = 0; i < numSubComponents; i++) {

			monitor.checkCanceled();
			Data subComponent = component.getComponent(i);
			getScalarsFromCompositeData(data, subComponent, monitor);
		}
	}

	private void addScalarFromData(Data data) {

		Scalar scalar = getScalarFromData(data);
		if (scalar == null) {
			return;
		}

		addMatch(new ScalarRowObject(data, scalar));
	}

	private void addDataFromComponent(Data data, Data component) {

		Scalar scalar = getScalarFromData(component);
		if (scalar == null) {
			return;
		}

		addMatch(new ScalarRowObject(component, scalar));
	}

	@Override
	public ProgramSelection getProgramSelection(int[] rows) {

		AddressSet set = new AddressSet();

		for (int element : rows) {
			ScalarRowObject rowObject = getRowObject(element);
			CodeUnit cu = rowObject.getCodeUnit();
			set.addRange(cu.getMinAddress(), cu.getMaxAddress());
		}

		return new ProgramSelection(set);
	}

	@Override
	public Address getAddress(int row) {
		ScalarRowObject rowObject = getRowObject(row);
		return rowObject.getAddress();
	}

	private Scalar getScalarFromOperand(Object opObj, TaskMonitor monitor) {
		return opObj instanceof Scalar ? (Scalar) opObj : null;
	}

	private Scalar getScalarFromData(Data data) {

		if (data == null) {
			return null;
		}

		if (!data.isDefined()) {
			return null;
		}

		Object value = data.getValue();
		if (!(value instanceof Scalar)) {
			return null;
		}

		return (Scalar) value;
	}

//==================================================================================================
// Columns & Column helpers
//==================================================================================================	

	private class ScalarComparator implements Comparator<Scalar> {

		@Override
		public int compare(Scalar o1, Scalar o2) {

			// @formatter:off
			if (o1 == o2)   { return 0;}
			if (o1 == null) { return 1; }
			if (o2 == null) { return -1; }
			// @formatter:on

			// sort unsigned before signed
			if (o1.isSigned() != o2.isSigned()) {
				return (o1.isSigned() ? 1 : -1);
			}

			return o1.compareTo(o2);
		}

	}

	private abstract class AbstractScalarValueRenderer extends AbstractGColumnRenderer<Scalar> {
		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			JLabel label = (JLabel) super.getTableCellRendererComponent(data);

			Scalar value = (Scalar) data.getValue();
			String text = formatScalar(value);
			label.setText(text);
			label.setOpaque(true);
			setHorizontalAlignment(SwingConstants.RIGHT);
			return label;
		}

		protected abstract String formatScalar(Scalar scalar);

		@Override
		public ColumnConstraintFilterMode getColumnConstraintFilterMode() {
			return ColumnConstraintFilterMode.ALLOW_CONSTRAINTS_FILTER_ONLY;
		}

		@Override
		public String getFilterString(Scalar t, Settings settings) {
			return formatScalar(t);
		}
	}

	private abstract class AbstractScalarValueTableColumn
			extends AbstractDynamicTableColumn<ScalarRowObject, Scalar, Program>
			implements ProgramLocationTableColumn<ScalarRowObject, Scalar> {

		@Override
		public Comparator<Scalar> getComparator() {
			return new ScalarComparator();
		}

		@Override
		public ProgramLocation getProgramLocation(ScalarRowObject rowObject, Settings settings,
				Program p, ServiceProvider provider) {
			return new ProgramLocation(p, rowObject.getAddress());
		}
	}

	private class ScalarHexUnsignedValueTableColumn extends AbstractScalarValueTableColumn {

		private static final int HEXADECIMAL_COL_WIDTH = 100;

		AbstractScalarValueRenderer renderer = new AbstractScalarValueRenderer() {

			private static final int RADIX = 16;
			private static final boolean ZERO_PADDED = false;
			private static final boolean SHOW_SIGN = false;
			private static final String PREFIX = "0x";
			private static final String SUFFIX = "";

			@Override
			protected String formatScalar(Scalar scalar) {
				if (scalar == null) {
					return "";
				}

				return scalar.toString(RADIX, ZERO_PADDED, SHOW_SIGN, PREFIX, SUFFIX);
			}

			@Override
			protected void configureFont(JTable table, TableModel model, int column) {
				setFont(fixedWidthFont);
			}

			@Override
			public ColumnConstraintFilterMode getColumnConstraintFilterMode() {
				return ColumnConstraintFilterMode.ALLOW_ALL_FILTERS;
			}

		};

		@Override
		public String getColumnName() {
			return "Hex (Unsigned)";
		}

		@Override
		public int getColumnPreferredWidth() {
			return HEXADECIMAL_COL_WIDTH;
		}

		@Override
		public GColumnRenderer<Scalar> getColumnRenderer() {
			return renderer;
		}

		@Override
		public Scalar getValue(ScalarRowObject rowObject, Settings settings, Program p,
				ServiceProvider provider) throws IllegalArgumentException {
			Scalar scalar = rowObject.getScalar();

			Scalar unsigned = new Scalar(scalar.bitLength(), scalar.getUnsignedValue(), false);
			return unsigned;

		}
	}

	private class ScalarSignedDecimalValueTableColumn extends AbstractScalarValueTableColumn {

		private static final int DECIMAL_COL_WIDTH = 100;

		AbstractScalarValueRenderer renderer = new AbstractScalarValueRenderer() {

			private static final int RADIX = 10;
			private static final boolean ZERO_PADDED = false;
			private static final boolean SHOW_SIGN = true;
			private static final String PREFIX = "";
			private static final String SUFFIX = "";

			@Override
			protected String formatScalar(Scalar scalar) {
				if (scalar == null) {
					return "";
				}

				return scalar.toString(RADIX, ZERO_PADDED, SHOW_SIGN, PREFIX, SUFFIX);
			}

		};

		@Override
		public String getColumnName() {
			return "Decimal (Signed)";
		}

		@Override
		public int getColumnPreferredWidth() {
			return DECIMAL_COL_WIDTH;
		}

		@Override
		public GColumnRenderer<Scalar> getColumnRenderer() {
			return renderer;
		}

		@Override
		public Scalar getValue(ScalarRowObject rowObject, Settings settings, Program p,
				ServiceProvider provider) throws IllegalArgumentException {
			Scalar scalar = rowObject.getScalar();

			Scalar signed = new Scalar(scalar.bitLength(), scalar.getUnsignedValue(), true);
			return signed;

		}

	}

	private class ScalarUnsignedDecimalValueTableColumn extends AbstractScalarValueTableColumn {

		private static final int DECIMAL_COL_WIDTH = 100;

		AbstractScalarValueRenderer renderer = new AbstractScalarValueRenderer() {

			private static final int RADIX = 10;
			private static final boolean ZERO_PADDED = false;
			private static final boolean SHOW_SIGN = false;
			private static final String PREFIX = "";
			private static final String SUFFIX = "";

			@Override
			protected String formatScalar(Scalar scalar) {
				if (scalar == null) {
					return "";
				}

				return scalar.toString(RADIX, ZERO_PADDED, SHOW_SIGN, PREFIX, SUFFIX);
			}

		};

		@Override
		public String getColumnName() {
			return "Decimal (Unsigned)";
		}

		@Override
		public int getColumnPreferredWidth() {
			return DECIMAL_COL_WIDTH;
		}

		@Override
		public GColumnRenderer<Scalar> getColumnRenderer() {
			return renderer;
		}

		@Override
		public Scalar getValue(ScalarRowObject rowObject, Settings settings, Program p,
				ServiceProvider provider) throws IllegalArgumentException {
			Scalar scalar = rowObject.getScalar();

			Scalar unsigned = new Scalar(scalar.bitLength(), scalar.getUnsignedValue(), false);
			return unsigned;

		}

	}

	private class ScalarBitCountTableColumn
			extends AbstractDynamicTableColumn<ScalarRowObject, Integer, Program>
			implements ProgramLocationTableColumn<ScalarRowObject, Integer> {

		private static final int BIT_COUNT_COL_WIDTH = 80;

		@Override
		public String getColumnName() {
			return "Bits";
		}

		@Override
		public Integer getValue(ScalarRowObject rowObject, Settings settings, Program p,
				ServiceProvider provider) throws IllegalArgumentException {
			return rowObject.getScalar().bitLength();
		}

		@Override
		public ProgramLocation getProgramLocation(ScalarRowObject rowObject, Settings settings,
				Program p, ServiceProvider provider) {
			return new ProgramLocation(program, rowObject.getAddress());
		}

		@Override
		public int getColumnPreferredWidth() {
			return BIT_COUNT_COL_WIDTH;
		}

	}

	public static enum Signedness {
		Signed, Unsigned

	}

	private class ScalarSignednessTableColumn
			extends AbstractDynamicTableColumn<ScalarRowObject, Signedness, Program>
			implements ProgramLocationTableColumn<ScalarRowObject, Signedness> {

		private static final int SIGNEDNESS_COL_WIDTH = 100;

		@Override
		public String getColumnName() {
			return "Signedness";
		}

		@Override
		public Signedness getValue(ScalarRowObject rowObject, Settings settings, Program p,
				ServiceProvider provider) throws IllegalArgumentException {
			return rowObject.getScalar().isSigned() ? Signedness.Signed : Signedness.Unsigned;
		}

		@Override
		public ProgramLocation getProgramLocation(ScalarRowObject rowObject, Settings settings,
				Program p, ServiceProvider provider) {
			return new ProgramLocation(program, rowObject.getAddress());
		}

		@Override
		public int getColumnPreferredWidth() {
			return SIGNEDNESS_COL_WIDTH;
		}

	}

	private class ScalarFunctionNameTableColumn extends FunctionNameTableColumn {

		private static final int FUNCTION_COL_WIDTH = 150;

		@Override
		public int getColumnPreferredWidth() {
			return FUNCTION_COL_WIDTH;
		}
	}
}
