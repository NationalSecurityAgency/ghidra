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
package ghidra.machinelearning.functionfinding;

import java.util.Map;
import java.util.Map.Entry;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link AddressBasedTableModel} used to display information about addresses which are
 * likely to be function starts.
 */
public class FunctionStartTableModel extends AddressBasedTableModel<FunctionStartRowObject> {
	private RandomForestRowObject modelRow;
	private AddressSet addressesToClassify;
	private boolean debug;
	private BasicBlockModel blockModel;
	private Map<Address, Double> addressToProbability;

	/**
	 * Creates a table to display address likely to be function starts. If {@code debug}
	 * is {@code true}, the table will contain a row for each address in 
	 * {@code addressesToClassify}.  Otherwise it will only contain rows for addresses whose
	 * associated probability is >= 0.5
	 * @param plugin owning plugin
	 * @param program source program
	 * @param toClassify addresses to search
	 * @param modelRow trained model info
	 * @param debug is table displaying debug data
	 */
	public FunctionStartTableModel(PluginTool plugin, Program program, AddressSet toClassify,
			RandomForestRowObject modelRow, boolean debug) {
		super(program.getName(), plugin, program, null, false);
		this.modelRow = modelRow;
		this.addressesToClassify = toClassify;
		this.debug = debug;
		blockModel = new BasicBlockModel(program);
	}

	@Override
	public Address getAddress(int row) {
		return getRowObject(row).getAddress();
	}

	@Override
	protected void doLoad(Accumulator<FunctionStartRowObject> accumulator, TaskMonitor monitor)
			throws CancelledException {
		//table might change as users create functions/disassemble code, so this method
		//may be called repeatedly.  However, the probabilities don't change, so only
		//compute the probability that an address is a function start once.
		if (addressToProbability == null) {
			FunctionStartClassifier classifier = new FunctionStartClassifier(program, modelRow,
				RandomForestFunctionFinderPlugin.FUNC_START);
			//if debug, we want to display all errors in the test set
			//if we left the prob threshold at .5 we would not see true function starts
			//that the models thinks are not function starts 
			if (debug) {
				classifier.setProbabilityThreshold(0.0);
			}
			addressToProbability = classifier.classify(addressesToClassify, monitor);
		}
		for (Entry<Address, Double> entry : addressToProbability.entrySet()) {
			Address addr = entry.getKey();
			FunctionStartRowObject rowObject = new FunctionStartRowObject(addr, entry.getValue());
			setInterpretation(rowObject, monitor);
			FunctionStartRowObject.setReferenceData(rowObject, program);
			accumulator.add(rowObject);
		}
	}

	@Override
	protected TableColumnDescriptor<FunctionStartRowObject> createTableColumnDescriptor() {
		TableColumnDescriptor<FunctionStartRowObject> descriptor = new TableColumnDescriptor<>();
		descriptor.addVisibleColumn(new AddressTableColumn());
		descriptor.addVisibleColumn(new ProbabilityTableColumn(), 0, false);
		descriptor.addVisibleColumn(new InterpretationTableColumn());
		descriptor.addVisibleColumn(new DataReferencesTableColumn());
		descriptor.addVisibleColumn(new UnconditionalFlowReferencesTableColumn());
		descriptor.addVisibleColumn(new ConditionalFlowReferencesTableColumn());
		return descriptor;
	}

	/**
	 * Returns the {@link RandomForestRowObject} corresponding to this row
	 * @return row object
	 */
	RandomForestRowObject getRandomForestRowObject() {
		return modelRow;
	}

	/**
	 * Determines and sets he {@link Interpretation} of the address corresponding to 
	 * {@code rowObject}.
	 * @param rowObject row of table
	 * @param monitor monitor
	 * @throws CancelledException if user cancels
	 */
	void setInterpretation(FunctionStartRowObject rowObject, TaskMonitor monitor)
			throws CancelledException {
		Interpretation inter =
			Interpretation.getInterpretation(program, rowObject.getAddress(), blockModel, monitor);
		rowObject.setCurrentInterpretation(inter);
	}

	private class AddressTableColumn
			extends AbstractDynamicTableColumn<FunctionStartRowObject, Address, Object> {

		@Override
		public String getColumnName() {
			return "Address";
		}

		@Override
		public Address getValue(FunctionStartRowObject rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.getAddress();
		}
	}

	private class ProbabilityTableColumn
			extends AbstractDynamicTableColumn<FunctionStartRowObject, Double, Object> {

		@Override
		public String getColumnName() {
			return "Probability";
		}

		@Override
		public Double getValue(FunctionStartRowObject rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.getProbability();
		}
	}

	private class InterpretationTableColumn
			extends AbstractDynamicTableColumn<FunctionStartRowObject, Interpretation, Object> {

		@Override
		public String getColumnName() {
			return "Interpretation";
		}

		@Override
		public Interpretation getValue(FunctionStartRowObject rowObject, Settings settings,
				Object data, ServiceProvider services) throws IllegalArgumentException {
			return rowObject.getCurrentInterpretation();
		}
	}

	private class DataReferencesTableColumn
			extends AbstractDynamicTableColumn<FunctionStartRowObject, Integer, Object> {

		@Override
		public String getColumnName() {
			return "Data Refs";
		}

		@Override
		public Integer getValue(FunctionStartRowObject rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.getNumDataRefs();
		}
	}

	private class UnconditionalFlowReferencesTableColumn
			extends AbstractDynamicTableColumn<FunctionStartRowObject, Integer, Object> {

		@Override
		public String getColumnName() {
			return "Unconditional Flow Refs";
		}

		@Override
		public Integer getValue(FunctionStartRowObject rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.getNumUnconditionalFlowRefs();
		}
	}

	private class ConditionalFlowReferencesTableColumn
			extends AbstractDynamicTableColumn<FunctionStartRowObject, Integer, Object> {

		@Override
		public String getColumnName() {
			return "Conditional Flow Refs";
		}

		@Override
		public Integer getValue(FunctionStartRowObject rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.getNumConditionalFlowRefs();
		}
	}

}
