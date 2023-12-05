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
package ghidra.features.bsim.gui.overview;

import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.table.TableModel;

import docking.widgets.table.*;
import generic.lsh.vector.LSHVectorFactory;
import ghidra.docking.settings.Settings;
import ghidra.features.bsim.gui.search.results.BSimMatchResultsModel;
import ghidra.features.bsim.query.protocol.ResponseNearestVector;
import ghidra.features.bsim.query.protocol.SimilarityVectorResult;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn;
import ghidra.util.table.field.AddressTableColumn;
import ghidra.util.task.TaskMonitor;

/**
 * Table model for BSim Overview results
 */
public class BSimOverviewModel extends AddressBasedTableModel<BSimOverviewRowObject> {

	static final int NAME_COL = 0;
	static final int HIT_COL = 1;
	static final int SELF_COL = 2;
	static final int ADDRESS_COL = 3;

	private List<BSimOverviewRowObject> results = new ArrayList<BSimOverviewRowObject>();
	private LSHVectorFactory vectorFactory;

	BSimOverviewModel(PluginTool tool, Program program, LSHVectorFactory vFactory) {
		super("Query Overview", tool, null, null);
		vectorFactory = vFactory;
		setProgram(program);
	}

	@Override
	protected TableColumnDescriptor<BSimOverviewRowObject> createTableColumnDescriptor() {
		TableColumnDescriptor<BSimOverviewRowObject> descriptor =
			new TableColumnDescriptor<BSimOverviewRowObject>();

		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new AddressTableColumn()), 1, true);
		descriptor.addVisibleColumn(new FuncNameColumn());
		descriptor.addVisibleColumn(new HitCountColumn());
		descriptor.addVisibleColumn(new SelfSignificanceColumn());
		descriptor.addHiddenColumn(new VectorHashColumn());
		return descriptor;
	}

	@Override
	public Address getAddress(int row) {
		return getRowObject(row).getFunctionEntryPoint();
	}

	@Override
	protected void doLoad(Accumulator<BSimOverviewRowObject> accumulator, TaskMonitor monitor)
			throws CancelledException {
		if (results.isEmpty()) {
			return;
		}

		for (BSimOverviewRowObject row : results) {
			accumulator.add(row);
		}
	}

	void addResult(ResponseNearestVector response) {
		if (response == null) {
			return; // not sure if this can happen
		}

		for (SimilarityVectorResult result : response.result) {
			Address addr = BSimMatchResultsModel.recoverAddress(result.getBase(), program);
			BSimOverviewRowObject row = new BSimOverviewRowObject(result, addr, vectorFactory);
			addObject(row);
		}
	}

	void reload(Program newProgram, ResponseNearestVector response) {
		setProgram(newProgram);
		if ((response == null) || response.result.isEmpty()) {
			clear();
			return;
		}

		results.clear();
		for (SimilarityVectorResult result : response.result) {
			Address addr = BSimMatchResultsModel.recoverAddress(result.getBase(), program);
			BSimOverviewRowObject row = new BSimOverviewRowObject(result, addr, vectorFactory);
			results.add(row);
		}
		super.reload();
	}

	void clear() {
		clearData();
	}

	//==================================================================================================
	// Inner Classes
	//==================================================================================================

	private static class FuncNameColumn
			extends AbstractProgramBasedDynamicTableColumn<BSimOverviewRowObject, String> {

		@Override
		public String getColumnName() {
			return "Function Name";
		}

		@Override
		public String getValue(BSimOverviewRowObject rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getFunctionName();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 400;
		}

	}

	private static class HitCountColumn
			extends AbstractProgramBasedDynamicTableColumn<BSimOverviewRowObject, Integer> {

		@Override
		public String getColumnName() {
			return "Hit Count";
		}

		@Override
		public Integer getValue(BSimOverviewRowObject rowObject, Settings settings, Program data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getHitCount();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 200;
		}

	}

	private static class SelfSignificanceColumn
			extends AbstractProgramBasedDynamicTableColumn<BSimOverviewRowObject, Double> {

		@Override
		public String getColumnName() {
			return "Self Significance";
		}

		@Override
		public Double getValue(BSimOverviewRowObject rowObject, Settings settings, Program data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getSelfSignificance();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 200;
		}
	}

	private static class VectorHashColumn
			extends AbstractProgramBasedDynamicTableColumn<BSimOverviewRowObject, Long> {
		private LongHexRenderer hexRenderer = new LongHexRenderer();

		@Override
		public String getColumnName() {
			return "Vector Hash";
		}

		@Override
		public Long getValue(BSimOverviewRowObject rowObject, Settings settings, Program data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getVectorHash();
		}

		@Override
		public GColumnRenderer<Long> getColumnRenderer() {
			return hexRenderer;
		}

		@Override
		public int getColumnPreferredWidth() {
			return 200;
		}

	}

	private static class LongHexRenderer extends AbstractGColumnRenderer<Long> {

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			JLabel label = (JLabel) super.getTableCellRendererComponent(data);
			label.setHorizontalAlignment(RIGHT);
			Long value = (Long) data.getValue();

			if (value != null) {
				label.setText(getValueString(value));
			}
			return label;
		}

		@Override
		protected void configureFont(JTable table, TableModel model, int column) {
			setFont(fixedWidthFont);
		}

		@Override
		public String getFilterString(Long t, Settings settings) {
			return getValueString(t);
		}

		private String getValueString(Long v) {
			if (v == null) {
				return "";
			}
			return String.format("%016X", v);
		}
	}

}
