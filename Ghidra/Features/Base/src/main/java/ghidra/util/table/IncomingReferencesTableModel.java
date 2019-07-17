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
package ghidra.util.table;

import java.util.List;

import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.field.OutgoingReferenceEndpoint;
import ghidra.util.table.field.ReferenceEndpoint;
import ghidra.util.task.TaskMonitor;

public class IncomingReferencesTableModel extends AddressBasedTableModel<ReferenceEndpoint> {

	private List<OutgoingReferenceEndpoint> refs;

	public IncomingReferencesTableModel(String title, ServiceProvider serviceProvider,
			Program program, List<OutgoingReferenceEndpoint> references, TaskMonitor monitor) {
		super(title, serviceProvider, program, monitor);
		this.refs = references;
	}

	@Override
	public Address getAddress(int row) {
		return getRowObject(row).getAddress();
	}

	@Override
	protected void doLoad(Accumulator<ReferenceEndpoint> accumulator, TaskMonitor monitor)
			throws CancelledException {

		refs.forEach(r -> accumulator.add(r));
	}
}
