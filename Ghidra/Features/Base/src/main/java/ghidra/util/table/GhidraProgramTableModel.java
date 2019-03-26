/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.util.table;

import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import docking.widgets.table.threaded.ThreadedTableModel;

public abstract class GhidraProgramTableModel<ROW_TYPE> extends
		ThreadedTableModel<ROW_TYPE, Program> implements ProgramTableModel {

	protected Program program;

	protected GhidraProgramTableModel(String modelName, ServiceProvider serviceProvider,
			Program program, TaskMonitor monitor) {
		this(modelName, serviceProvider, program, monitor, false);
	}

	protected GhidraProgramTableModel(String modelName, ServiceProvider serviceProvider,
			Program program, TaskMonitor monitor, boolean loadIncrementally) {
		super(modelName, serviceProvider, monitor, loadIncrementally);
		this.program = program;
	}

	public void setProgram(Program program) {
		Program originalProgram = this.program;
		this.program = program;

		if (originalProgram != program) {
			clearData();
		}
	}

	/**
	 * Extension point for getting a row-specific program.  Most models don't need this 
	 * capability. 
	 * @param t The ROW_TYPE row object
	 */
	protected Program getProgramForRow(ROW_TYPE t) {
		return getProgram();
	}

	@Override
	public Program getProgram() {
		return program;
	}

	@Override
	public Program getDataSource() {
		return getProgram();
	}
}
