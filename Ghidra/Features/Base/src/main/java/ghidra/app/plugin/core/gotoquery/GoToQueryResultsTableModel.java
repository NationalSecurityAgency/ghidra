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
package ghidra.app.plugin.core.gotoquery;

import java.util.List;

import ghidra.app.util.query.ProgramLocationPreviewTableModel;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GoToQueryResultsTableModel extends ProgramLocationPreviewTableModel {
	private List<ProgramLocation> locations;

	public GoToQueryResultsTableModel(Program prog, ServiceProvider serviceProvider,
			List<ProgramLocation> locations, TaskMonitor monitor) {
		super("Goto", serviceProvider, prog, monitor);
		this.locations = locations;
	}

	@Override
	public Address getAddress(int row) {
		return filteredData.get(row).getAddress();
	}

	@Override
	protected void doLoad(Accumulator<ProgramLocation> accumulator, TaskMonitor monitor)
			throws CancelledException {

		if (locations != null) {
			accumulator.addAll(locations);
			locations = null;
			return;
		}
	}
}
