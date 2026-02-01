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

import java.util.*;

import docking.widgets.table.TableColumnDescriptor;
import ghidra.docking.settings.Settings;
import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.GhidraProgramTableModel;
import ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn;
import ghidra.util.task.TaskMonitor;

/**
 * Table model built by aggregating or "summing" the columns of rows from the QueryResultModel.
 * QueryResultModel rows represent functions contained in specific executables.
 * This model groups function rows from the same executable and produces a single
 * row for that executable.  Columns are populated roughly:
 *    CountColumn is the number of functions in the group
 *    SignificanceColumn is the sum of the individual function significances in the group
 *  All the other columns are inherited from properties of the single executable used
 *  to define the group of functions.
 *    ExecutableNameMatch        name of the executable
 *    ExecutableCategoryMatch    a category associated with the executable    
 *    ExecutableDateMatch        date associated with the executable
 *    ArchitectureMatch          architecture
 *    CompilerMatch              compiler
 *    RepoColumn                 repository containing the executable
 *
 */
public class BSimExecutablesSummaryModel extends GhidraProgramTableModel<ExecutableResult> {
	private Collection<ExecutableResult> results;

	BSimExecutablesSummaryModel(PluginTool tool, DatabaseInformation info) {
		super("Executable Sum", tool, null, null);
		addCustomColumns(info);
	}

	private void addCustomColumns(DatabaseInformation info) {
		if (info == null) {
			return; // Info can be null, even if FunctionDatabase return Ready  (not created yet)
		}
		if (info.execats != null) {
			for (int i = 0; i < info.execats.size(); ++i) {
				addTableColumn(new ExecutableCategoryMatchColumn(info.execats.get(i)));
			}
		}
		if (info.dateColumnName != null) {
			addTableColumn(new ExecutableDateMatchColumn(info.dateColumnName));
		}
		else {
			addTableColumn(new ExecutableDateMatchColumn("Ingest Date"));
		}
	}

	@Override
	protected TableColumnDescriptor<ExecutableResult> createTableColumnDescriptor() {
		TableColumnDescriptor<ExecutableResult> descriptor =
			new TableColumnDescriptor<ExecutableResult>();

		descriptor.addVisibleColumn(new ExecutableNameMatchColumn());
		descriptor.addHiddenColumn(new ArchitectureMatchColumn());
		descriptor.addHiddenColumn(new CompilerMatchColumn());
		descriptor.addVisibleColumn(new CountColumn());
		descriptor.addVisibleColumn(new SignificanceColumn());
		descriptor.addHiddenColumn(new RepoColumn());

		return descriptor;
	}

	@Override
	protected void doLoad(Accumulator<ExecutableResult> accumulator, TaskMonitor monitor)
			throws CancelledException {
		if ((results == null) || (results.isEmpty())) {
			return;
		}

		Iterator<ExecutableResult> iter = results.iterator();
		while (iter.hasNext()) {
			accumulator.add(iter.next());
		}
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int column) {
		return null;
	}

	@Override
	public ProgramSelection getProgramSelection(int[] rows) {
		// We could conceivably collect addresses of all functions that are matching into a specific executable
		return new ProgramSelection();
	}

	void reload(Program newProgram, Collection<ExecutableResult> set) {
		setProgram(newProgram);
		results = set;
		reload();
	}

	void clear() {
		clearData();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	/**
	 * Column holding the name of an executable containing 1 or more functions in the result set
	 *
	 */
	private static class ExecutableNameMatchColumn
			extends AbstractProgramBasedDynamicTableColumn<ExecutableResult, String> {

		@Override
		public String getColumnName() {
			return "Exe Name";
		}

		@Override
		public String getValue(ExecutableResult rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getExecutableRecord().getNameExec();
		}
	}

	/**
	 * Column holding the value of an executable category for an
	 * executable containing 1 or more functions in the result set
	 *
	 */
	private static class ExecutableCategoryMatchColumn
			extends AbstractProgramBasedDynamicTableColumn<ExecutableResult, String> {
		private String columnName;

		public ExecutableCategoryMatchColumn(String name) {
			super("ExecutableCategoryMatchColumn: " + name);
			columnName = name;
		}

		@Override
		public String getColumnName() {
			return columnName;
		}

		@Override
		public String getValue(ExecutableResult rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getExecutableRecord().getExeCategoryAlphabetic(columnName);
		}

	}

	/**
	 * Column holding the date for an executable containing 1 or more functions in the result set
	 *
	 */
	private static class ExecutableDateMatchColumn
			extends AbstractProgramBasedDynamicTableColumn<ExecutableResult, Date> {

		private String columnName;

		public ExecutableDateMatchColumn(String name) {
			columnName = name;
		}

		@Override
		public String getColumnName() {
			return columnName;
		}

		@Override
		public Date getValue(ExecutableResult rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getExecutableRecord().getDate();
		}
	}

	/**
	 * Column holding the architecture for an executable containing 1 or more functions in the result set
	 *
	 */
	private static class ArchitectureMatchColumn
			extends AbstractProgramBasedDynamicTableColumn<ExecutableResult, String> {

		@Override
		public String getColumnName() {
			return "Architecture";
		}

		@Override
		public String getValue(ExecutableResult rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getExecutableRecord().getArchitecture();
		}
	}

	/**
	 * Column holding the compiler for an executable containing 1 or more functions in the result set
	 *
	 */
	private static class CompilerMatchColumn
			extends AbstractProgramBasedDynamicTableColumn<ExecutableResult, String> {

		@Override
		public String getColumnName() {
			return "Compiler";
		}

		@Override
		public String getValue(ExecutableResult rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getExecutableRecord().getNameCompiler();
		}
	}

	/**
	 * Column holding the number of functions in the result set from a single executable
	 *
	 */
	private static class CountColumn
			extends AbstractProgramBasedDynamicTableColumn<ExecutableResult, Integer> {

		@Override
		public String getColumnName() {
			return "Function Count";
		}

		@Override
		public Integer getValue(ExecutableResult rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return Integer.valueOf(rowObject.getFunctionCount());
		}
	}

	/**
	 * Column holding the sum of significance scores for functions in the result set from a single executable
	 *
	 */
	private static class SignificanceColumn
			extends AbstractProgramBasedDynamicTableColumn<ExecutableResult, Double> {

		@Override
		public String getColumnName() {
			return "Confidence";
		}

		@Override
		public Double getValue(ExecutableResult rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return Double.valueOf(rowObject.getSignificanceSum());
		}
	}

	/**
	 * Column holding the repository URL for an executable containing 1 or more functions in the result set
	 *
	 */
	private static class RepoColumn
			extends AbstractProgramBasedDynamicTableColumn<ExecutableResult, String> {

		@Override
		public String getColumnName() {
			return "URL";
		}

		@Override
		public String getValue(ExecutableResult rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			String urlstring = rowObject.getExecutableRecord().getURLString();
			if (urlstring == null) {
				return "none";
			}
			return urlstring;
		}
	}
}
