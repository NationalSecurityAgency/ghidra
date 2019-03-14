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
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class AddressSetTableModel extends AddressPreviewTableModel {

	private AddressSetView addressSet;

	public AddressSetTableModel(String title, ServiceProvider serviceProvider, Program prog,
			AddressSetView addressSet, TaskMonitor monitor) {
		super(title, serviceProvider, prog, monitor);
		this.addressSet = addressSet;
	}

	@Override
	protected void doLoad(Accumulator<Address> accumulator, TaskMonitor monitor)
			throws CancelledException {

		monitor.initialize(addressSet.getNumAddresses());
		AddressIterator iterator = addressSet.getAddresses(true);
		for (Address address : iterator) {
			monitor.checkCanceled();
			accumulator.add(address);
			monitor.incrementProgress(1);
		}
	}
}
