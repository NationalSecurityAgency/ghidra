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

import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Table model that shows a location, label, and a preview column to
 * show a preview of the code unit. The location can be in a memory address,
 * a stack address, or a register address. The label is the primary symbol
 * at the address, if one exists. Use this model when you have a list of
 * addresses to build up dynamically.
 */
public abstract class AddressPreviewTableModel extends AddressBasedTableModel<Address> {

	/**
	 * Constructor.
	 * 
	 * @param modelName the name of the model (used for the title)
	 * @param serviceProvider from which to get services
	 * @param program the program upon which this model is being used
	 * @param monitor the monitor to use for tracking progress and cancelling; may be null
	 */
	protected AddressPreviewTableModel(String modelName, ServiceProvider serviceProvider,
			Program program, TaskMonitor monitor) {
		this(modelName, serviceProvider, program, monitor, false);
	}

	/**
	 * Constructor.
	 * 
	 * @param modelName the name of the model (used for the title)
	 * @param serviceProvider from which to get services
	 * @param program the program upon which this model is being used
	 * @param monitor the monitor to use for tracking progress and cancelling; may be null
	 * @param loadIncrementally true signals to show table results as they come in
	 */
	protected AddressPreviewTableModel(String modelName, ServiceProvider serviceProvider,
			Program program, TaskMonitor monitor, boolean loadIncrementally) {
		super(modelName, serviceProvider, program, monitor, loadIncrementally);
	}

	@Override
	public Address getAddress(int row) {
		return getRowObject(row);
	}
}
