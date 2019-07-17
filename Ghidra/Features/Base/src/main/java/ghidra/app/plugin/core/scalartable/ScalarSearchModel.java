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

import javax.swing.*;
import javax.swing.table.TableModel;

import docking.widgets.table.*;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.*;
import ghidra.program.model.data.Resource;
import ghidra.program.model.lang.Register;
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

	private static final int FUNCTION_COL_WIDTH = 150;
	private static final int HEXADECIMAL_COL_WIDTH = 100;
	private static final int DECIMAL_COL_WIDTH = 100;

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
		descriptor.addVisibleColumn(new ScalarHexValueTableColumn());
		descriptor.addVisibleColumn(new ScalarSignedDecimalValueTableColumn());
		descriptor.addHiddenColumn(new ScalarUnsignedDecimalValueTableColumn());
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new ScalarFunctionNameTableColumn()));

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
					getScalarFromInstruction(instruction, opObjs, monitor);
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

	private void getScalarFromInstruction(Instruction instruction, Object[] opObjs,
			TaskMonitor monitor) throws CancelledException {

		Scalar scalar = getScalarFromOperand(opObjs, monitor);
		if (scalar != null) {
			addMatch(new ScalarRowObject(instruction, scalar));
		}
	}

	private void addMatch(ScalarRowObject rowObject) {

		if (rowObject == null) {
			return;
		}

		Scalar scalar = rowObject.getScalar();
		long value = scalar.getSignedValue();
		if (value < minValue) {
			return;
		}

		if (value > maxValue) {
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

	private Scalar getScalarFromOperand(Object[] opObjs, TaskMonitor monitor)
			throws CancelledException {

		if (opObjs == null) {
			return null;
		}

		Object obj = null;
		for (Object opObj : opObjs) {
			monitor.checkCanceled();
			if (opObj instanceof Register) {
				return null;
			}

			if (opObj instanceof Scalar) {
				obj = opObj;
			}
		}
		return (Scalar) obj;
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
// Columns
//==================================================================================================	

	private class ScalarHexValueTableColumn
			extends AbstractDynamicTableColumn<ScalarRowObject, Scalar, Program>
			implements ProgramLocationTableColumn<ScalarRowObject, Scalar> {

		private GColumnRenderer<Scalar> renderer = new AbstractGColumnRenderer<Scalar>() {
			@Override
			public Component getTableCellRendererComponent(GTableCellRenderingData data) {

				JLabel label = (JLabel) super.getTableCellRendererComponent(data);

				Scalar value = (Scalar) data.getValue();
				String text = asString(value);
				label.setText(text);
				label.setOpaque(true);
				setHorizontalAlignment(SwingConstants.RIGHT);
				return label;
			}

			private String asString(Scalar s) {
				if (s == null) {
					return "";
				}
				return s.toString(16, false, false, "", "");
			}

			@Override
			protected void configureFont(JTable table, TableModel model, int column) {
				setFont(getFixedWidthFont());
			}

			@Override
			public String getFilterString(Scalar t, Settings settings) {
				return asString(t);
			}

		};

		@Override
		public String getColumnName() {
			return "Hex";
		}

		@Override
		public int getColumnPreferredWidth() {
			return HEXADECIMAL_COL_WIDTH;
		}

		@Override
		public Scalar getValue(ScalarRowObject rowObject, Settings settings, Program p,
				ServiceProvider provider) throws IllegalArgumentException {
			return rowObject.getScalar();
		}

		@Override
		public ProgramLocation getProgramLocation(ScalarRowObject rowObject, Settings settings,
				Program p, ServiceProvider provider) {
			return new ProgramLocation(program, rowObject.getAddress());
		}

		@Override
		public GColumnRenderer<Scalar> getColumnRenderer() {
			return renderer;
		}
	}

	private class ScalarSignedDecimalValueTableColumn
			extends AbstractDynamicTableColumn<ScalarRowObject, Long, Program>
			implements ProgramLocationTableColumn<ScalarRowObject, Long> {

		@Override
		public String getColumnName() {
			return "Decimal (Signed)";
		}

		@Override
		public int getColumnPreferredWidth() {
			return DECIMAL_COL_WIDTH;
		}

		@Override
		public Long getValue(ScalarRowObject rowObject, Settings settings, Program p,
				ServiceProvider provider) throws IllegalArgumentException {

			return rowObject.getScalar().getSignedValue();
		}

		@Override
		public ProgramLocation getProgramLocation(ScalarRowObject rowObject, Settings settings,
				Program p, ServiceProvider provider) {
			return new ProgramLocation(program, rowObject.getAddress());
		}
	}

	private class ScalarUnsignedDecimalValueTableColumn
			extends AbstractDynamicTableColumn<ScalarRowObject, Long, Program>
			implements ProgramLocationTableColumn<ScalarRowObject, Long> {

		@Override
		public String getColumnName() {
			return "Decimal (Unsigned)";
		}

		@Override
		public int getColumnPreferredWidth() {
			return DECIMAL_COL_WIDTH;
		}

		@Override
		public Long getValue(ScalarRowObject rowObject, Settings settings, Program p,
				ServiceProvider provider) throws IllegalArgumentException {

			return rowObject.getScalar().getUnsignedValue();
		}

		@Override
		public ProgramLocation getProgramLocation(ScalarRowObject rowObject, Settings settings,
				Program p, ServiceProvider provider) {
			return new ProgramLocation(program, rowObject.getAddress());
		}
	}

	private class ScalarFunctionNameTableColumn extends FunctionNameTableColumn {

		@Override
		public int getColumnPreferredWidth() {
			return FUNCTION_COL_WIDTH;
		}
	}
}
