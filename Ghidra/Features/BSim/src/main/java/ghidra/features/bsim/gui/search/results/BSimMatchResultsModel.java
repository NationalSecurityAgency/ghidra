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
package ghidra.features.bsim.gui.search.results;

import static ghidra.features.bsim.gui.search.results.BSimResultStatus.*;

import java.awt.Component;
import java.util.*;

import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.table.TableModel;

import docking.widgets.table.*;
import generic.lsh.vector.LSHVectorFactory;
import ghidra.app.util.NamespaceUtils;
import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.features.bsim.gui.filters.FunctionTagBSimFilterType;
import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.features.bsim.query.description.FunctionDescription;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.table.field.*;
import ghidra.util.task.TaskMonitor;

/**
 * Table model for BSim Similar function search results
 */
public class BSimMatchResultsModel extends AddressBasedTableModel<BSimMatchResult> {
	private static final ShowNamespaceSettingsDefinition SHOW_NAMESPACE =
		ShowNamespaceSettingsDefinition.DEF;
	private static SettingsDefinition[] SETTINGS_DEFS = { SHOW_NAMESPACE };
	private Collection<BSimMatchResult> results = new ArrayList<BSimMatchResult>();

	// Maps functions (represented by addresses) to the number of matches in the query.
	// This is here to provide quick access for the MatchCountTableColumn. 
	private Map<Address, Integer> functionMatchMap = new HashMap<>();

	public BSimMatchResultsModel(PluginTool tool, DatabaseInformation info,
			LSHVectorFactory lshVectorFactory) {
		super("Query Results", tool, null, null);
		addCustomColumns(info, lshVectorFactory);
	}

	private void addCustomColumns(DatabaseInformation info, LSHVectorFactory lshVectorFactory) {
		if (info == null) {
			return; // Info can be null, even if FunctionDatabase return Ready  (not created yet)
		}
		if (info.execats != null) {
			for (int i = 0; i < info.execats.size(); ++i) {
				addTableColumn(new ExecCategoryColumn(info.execats.get(i)));
			}
		}
		if (info.functionTags != null) {
			int mask = 1;
			mask <<= FunctionTagBSimFilterType.RESERVED_BITS;
			for (int i = 0; i < info.functionTags.size(); ++i) {
				addTableColumn(new FunctionTagColumn(info.functionTags.get(i), mask));
				mask <<= 1;
			}
		}
		if (info.dateColumnName != null) {
			addTableColumn(new ExecDateColumn(info.dateColumnName));
		}
		else {
			addTableColumn(new ExecDateColumn("Ingest Date"));
		}

		// Must add this column here because it requires that the queryManager
		// be available. At the time createTableColumnDescriptor() is called this 
		// is not the case. The index is set to '-1' so it will be placed at the end
		// of the list.
		if (lshVectorFactory != null) {
			addTableColumn(new SelfSignificanceColumn(lshVectorFactory), -1, false);
		}
	}

	@Override
	protected TableColumnDescriptor<BSimMatchResult> createTableColumnDescriptor() {
		TableColumnDescriptor<BSimMatchResult> descriptor =
			new TableColumnDescriptor<BSimMatchResult>();

		descriptor.addVisibleColumn(new StatusColumn());
		descriptor.addVisibleColumn(new SimilarityColumn());
		descriptor.addVisibleColumn(new SignificanceColumn(), 1, false);
		descriptor.addVisibleColumn(new QueryFunctionColumn());
		descriptor.addVisibleColumn(new FuncNameMatchColumn());
		descriptor.addVisibleColumn(new ExecNameMatchColumn());
		descriptor.addHiddenColumn(new ArchitectureMatchColumn());
		descriptor.addHiddenColumn(new ExecMd5Column());
		descriptor.addHiddenColumn(new CompilerMatchColumn());
		descriptor.addHiddenColumn(new MatchCountTableColumn());
		descriptor.addHiddenColumn(new FunctionSizeTableColumn());
		descriptor.addHiddenColumn(new FunctionTagColumn("Known Library",
			FunctionTagBSimFilterType.KNOWN_LIBRARY_MASK));
		descriptor.addHiddenColumn(new FunctionTagColumn("Has Unimplemented",
			FunctionTagBSimFilterType.HAS_UNIMPLEMENTED_MASK));
		descriptor.addHiddenColumn(new FunctionTagColumn("Has Bad Data",
			FunctionTagBSimFilterType.HAS_BADDATA_MASK));
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new AddressTableColumn()));
		descriptor.addHiddenColumn(new MatchingFunctionAddressTableColumn());

		return descriptor;
	}

	@Override
	public Address getAddress(int row) {
		int index = getColumnIndex(AddressTableColumn.class);
		return ((AddressBasedLocation) getValueAt(row, index)).getAddress();
	}

	@Override
	protected void doLoad(Accumulator<BSimMatchResult> accumulator, TaskMonitor monitor)
			throws CancelledException {

		if (results.isEmpty()) {
			return;
		}

		for (BSimMatchResult similarFunction : results) {
			accumulator.add(similarFunction);
		}
	}

	void addResult(Collection<BSimMatchResult> result) {
		if (result == null) {
			return; // not sure if this can happen
		}

		for (BSimMatchResult function : result) {
			addObject(function);
		}
	}

	void reload(Program newProgram, List<BSimMatchResult> rowset) {
		setProgram(newProgram);
		if (rowset == null) {
			clear();
			return;
		}

		results = rowset;

		parseFunctionMatchCounts(results);

		super.reload();
	}

	/**
	 * Parses the given result set to find the number of matches associated with 
	 * each base function. 
	 * 
	 * @param queryResults the query results to inspect
	 */
	private void parseFunctionMatchCounts(Collection<BSimMatchResult> queryResults) {
		// Begin with a clear map.
		functionMatchMap.clear();
		for (BSimMatchResult result : queryResults) {
			Address key = result.getAddress();
			functionMatchMap.put(key, functionMatchMap.getOrDefault(key, 0) + 1);
		}
	}

	void clear() {
		clearData();
	}

	/**
	 * Associate a given FunctionDescription with the entry point of the matching function in a program
	 * @param desc is the FunctionDescription to recover
	 * @param prog is the Program (possibly) containing the Function object 
	 * @return the entry point address of the function (if it exists), or just the address within the default space
	 */
	public static Address recoverAddress(FunctionDescription desc, Program prog) {
		Address address =
			prog.getAddressFactory().getDefaultAddressSpace().getAddress(desc.getAddress());
		// Verify that we got the right function
		Function func = prog.getFunctionManager().getFunctionAt(address);
		if (func != null) {
			if (func.getName(true).equals(desc.getFunctionName())) {
				return address;
			}
		}

		Function f = getUniqueFunction(desc, prog);
		if (f != null) {
			return f.getEntryPoint();
		}
		return address;
	}

	private static Function getUniqueFunction(FunctionDescription desc, Program prog) {
		Function f = null;
		for (Namespace namespace : NamespaceUtils.getNamespacesByName(prog, null,
			desc.getFunctionName())) {
			if (namespace instanceof Function) {
				if (f != null) {
					return null;
				}
				f = (Function) namespace;
			}
		}
		return f;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================
	private static class StatusColumn
			extends AbstractProgramBasedDynamicTableColumn<BSimMatchResult, BSimResultStatus> {
		private BSimStatusRenderer statusRenderer = new BSimStatusRenderer();

		@Override
		public String getColumnName() {
			return "Status";
		}

		@Override
		public BSimResultStatus getValue(BSimMatchResult rowObject, Settings settings,
				Program program, ServiceProvider serviceProvider) throws IllegalArgumentException {
			BSimResultStatus status = rowObject.getStatus();

			Function function = program.getFunctionManager().getFunctionAt(rowObject.getAddress());
			if (function == null) {
				return BSimResultStatus.NO_FUNCTION;
			}

			boolean nameMatches = hasMatchingFunctionName(function, rowObject);
			if (status == NAME_APPLIED) {
				return nameMatches ? NAME_APPLIED : APPLIED_NO_LONGER_MATCHES;
			}
			if (status == SIGNATURE_APPLIED) {
				return nameMatches ? SIGNATURE_APPLIED : APPLIED_NO_LONGER_MATCHES;
			}
			if (nameMatches) {
				return MATCHES;
			}
			return status == ERROR ? ERROR : NOT_APPLIED;
		}

		private boolean hasMatchingFunctionName(Function function, BSimMatchResult result) {
			String name = function.getName(true);
			String matchName = result.getSimilarFunctionName();
			return name.equals(matchName);
		}

		@Override
		public int getColumnPreferredWidth() {
			return 60;
		}

		@Override
		public GColumnRenderer<BSimResultStatus> getColumnRenderer() {
			return statusRenderer;
		}
	}

	private static class QueryFunctionColumn
			extends AbstractProgramBasedDynamicTableColumn<BSimMatchResult, String> {

		@Override
		public String getColumnName() {
			return "Function Name";
		}

		@Override
		public String getValue(BSimMatchResult rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			Address address = rowObject.getAddress();
			Function function = program.getFunctionManager().getFunctionAt(address);
			boolean showNamespace = SHOW_NAMESPACE.getValue(settings);
			if (function != null) {
				return function.getName(showNamespace);
			}
			return "Function Missing!";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 200;
		}

		@Override
		public SettingsDefinition[] getSettingsDefinitions() {
			return SETTINGS_DEFS;
		}
	}

	private static class FuncNameMatchColumn
			extends AbstractProgramBasedDynamicTableColumn<BSimMatchResult, String> {

		@Override
		public String getColumnName() {
			return "Matching Function Name";
		}

		@Override
		public String getValue(BSimMatchResult rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			String name = rowObject.getSimilarFunctionName();
			boolean showNamespace = SHOW_NAMESPACE.getValue(settings);
			if (!showNamespace) {
				int lastIndexOf = name.lastIndexOf("::");
				if (lastIndexOf > 0) {
					name = name.substring(lastIndexOf + 2);
				}
			}
			return name;
		}

		@Override
		public int getColumnPreferredWidth() {
			return 200;
		}

		@Override
		public SettingsDefinition[] getSettingsDefinitions() {
			return SETTINGS_DEFS;
		}
	}

	private static class ExecNameMatchColumn
			extends AbstractProgramBasedDynamicTableColumn<BSimMatchResult, String> {

		@Override
		public String getColumnName() {
			return "Exe Name";
		}

		@Override
		public String getValue(BSimMatchResult rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getExecutableName();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 200;
		}
	}

	/**
	 * Column for showing the number of matches each base function has.
	 * 
	 * Note the use of the {@link BSimMatchResultsModel#functionMatchMap}; this is
	 * for performance reasons. We don't want this class looping over the entire
	 * result set calculating match counts every time the table is refreshed.
	 *
	 */
	private class MatchCountTableColumn
			extends AbstractProgramBasedDynamicTableColumn<BSimMatchResult, Integer> {

		@Override
		public String getColumnName() {
			return "Matches";
		}

		@Override
		public Integer getValue(BSimMatchResult rowObject, Settings settings, Program program,
				ServiceProvider provider) throws IllegalArgumentException {
			return functionMatchMap.get(rowObject.getAddress());
		}

		@Override
		public int getColumnPreferredWidth() {
			return 50;
		}
	}

	/**
	 * Column for showing the address of the matching function.  
	 */
	private static class MatchingFunctionAddressTableColumn
			extends AbstractProgramBasedDynamicTableColumn<BSimMatchResult, Long> {
		private AddressOffsetHexRenderer renderer = new AddressOffsetHexRenderer();

		@Override
		public String getColumnName() {
			return "Matching Function Address";
		}

		@Override
		public Long getValue(BSimMatchResult rowObject, Settings settings, Program data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			Long addr = rowObject.getMatchFunctionDescription().getAddress();
			return addr;
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}

		@Override
		public GColumnRenderer<Long> getColumnRenderer() {
			return renderer;
		}
	}

	private static class AddressOffsetHexRenderer extends AbstractGColumnRenderer<Long> {

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
			String format = ((v & 0xffffffff00000000L) == 0L) ? "%08X" : "%016X";
			return String.format(format, v);
		}
	}

	private static class FunctionSizeTableColumn
			extends AbstractProgramBasedDynamicTableColumn<BSimMatchResult, Long> {

		@Override
		public String getColumnName() {
			return "Size";
		}

		@Override
		public Long getValue(BSimMatchResult rowObject, Settings settings, Program program,
				ServiceProvider provider) throws IllegalArgumentException {
			Address address = rowObject.getAddress();
			Function function = program.getFunctionManager().getFunctionAt(address);
			return function.getBody().getNumAddresses();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}
	}

	private static class ExecDateColumn
			extends AbstractProgramBasedDynamicTableColumn<BSimMatchResult, Date> {
		private String columnName;

		ExecDateColumn(String name) {
			super();
			columnName = name;
		}

		@Override
		public String getColumnName() {
			return columnName;
		}

		@Override
		public Date getValue(BSimMatchResult rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getDate();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}

	}

	private static class ExecCategoryColumn
			extends AbstractProgramBasedDynamicTableColumn<BSimMatchResult, String> {
		private String columnName;

		ExecCategoryColumn(String name) {
			super("ExecCategoryColumn: " + name);
			columnName = name;
		}

		@Override
		public String getColumnName() {
			return columnName;
		}

		@Override
		public String getValue(BSimMatchResult rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getExeCategoryAlphabetic(columnName);
		}

		@Override
		public int getColumnPreferredWidth() {
			return 200;
		}

	}

	private static class ArchitectureMatchColumn
			extends AbstractProgramBasedDynamicTableColumn<BSimMatchResult, String> {

		@Override
		public String getColumnName() {
			return "Architecture";
		}

		@Override
		public String getValue(BSimMatchResult rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getArchitecture();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}

	}

	private static class CompilerMatchColumn
			extends AbstractProgramBasedDynamicTableColumn<BSimMatchResult, String> {

		@Override
		public String getColumnName() {
			return "Compiler";
		}

		@Override
		public String getValue(BSimMatchResult rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getCompilerName();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}

	}

	private static class ExecMd5Column
			extends AbstractProgramBasedDynamicTableColumn<BSimMatchResult, String> {

		@Override
		public String getColumnName() {
			return "Md5";
		}

		@Override
		public String getValue(BSimMatchResult rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getMd5();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}

	}

	private static class SimilarityColumn
			extends AbstractProgramBasedDynamicTableColumn<BSimMatchResult, Double> {
		private DoubleRenderer doubleRenderer = new DoubleRenderer();

		@Override
		public String getColumnName() {
			return "Similarity";
		}

		@Override
		public Double getValue(BSimMatchResult rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getSimilarity();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}

		@Override
		public GColumnRenderer<Double> getColumnRenderer() {
			return doubleRenderer;
		}
	}

	private static class SignificanceColumn
			extends AbstractProgramBasedDynamicTableColumn<BSimMatchResult, Double> {
		private DoubleRenderer doubleRenderer = new DoubleRenderer();

		@Override
		public String getColumnName() {
			return "Confidence";
		}

		@Override
		public Double getValue(BSimMatchResult rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getSignificance();
		}

		@Override
		public GColumnRenderer<Double> getColumnRenderer() {
			return doubleRenderer;
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}
	}

	private static class SelfSignificanceColumn
			extends AbstractProgramBasedDynamicTableColumn<BSimMatchResult, Double> {

		private DoubleRenderer doubleRenderer = new DoubleRenderer();
		private LSHVectorFactory vectorFactory;

		public SelfSignificanceColumn(LSHVectorFactory vectorFactory) {
			this.vectorFactory = vectorFactory;
		}

		@Override
		public String getColumnName() {
			return "Matching Function Self Significance";
		}

		@Override
		public Double getValue(BSimMatchResult rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return vectorFactory.getSelfSignificance(
				rowObject.getMatchFunctionDescription().getSignatureRecord().getLSHVector());
		}

		@Override
		public GColumnRenderer<Double> getColumnRenderer() {
			return doubleRenderer;
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}
	}

	private static class FunctionTagColumn
			extends AbstractProgramBasedDynamicTableColumn<BSimMatchResult, Boolean> {
		private String columnName;
		private int mask; // Mask for this particular boolean value

		FunctionTagColumn(String name, int m) {
			super("Function Tag: " + name);
			columnName = name;
			mask = m;
		}

		@Override
		public String getColumnName() {
			return columnName;
		}

		@Override
		public Boolean getValue(BSimMatchResult rowObject, Settings settings, Program data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.isFlagSet(mask);
		}

		@Override
		public int getColumnPreferredWidth() {
			return 200;
		}
	}

	private static class DoubleRenderer extends AbstractGColumnRenderer<Double> {

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			JLabel label = (JLabel) super.getTableCellRendererComponent(data);
			Double value = (Double) data.getValue();

			if (value != null) {
				label.setText(formatNumber(value, data.getColumnSettings()));
				label.setToolTipText(value.toString());
			}
			else {
				label.setText("");
				label.setToolTipText(null);
			}
			return label;
		}

		@Override
		public String getFilterString(Double t, Settings settings) {
			return formatNumber(t, settings);
		}

		@Override
		public ColumnConstraintFilterMode getColumnConstraintFilterMode() {
			return ColumnConstraintFilterMode.ALLOW_CONSTRAINTS_FILTER_ONLY;
		}
	}
}
