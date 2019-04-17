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
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * An {@link Address} based table model that allows clients to load their data via 
 * the {@link TableModelLoader} callback provided at construction time.
 * <p>
 * Why?  Well, this allows clients to use the existing table model framework without
 * having to create a new table model.  In other words, some of the boilerplate code
 * of creating a model is removed--clients need only implement one method in order to
 * get full thread table functionality, which is a lot. 
 */
public class CustomLoadingAddressTableModel extends AddressPreviewTableModel {

	private TableModelLoader<Address> loader;

	public CustomLoadingAddressTableModel(String modelName, ServiceProvider serviceProvider,
			Program program, TableModelLoader<Address> loader, TaskMonitor monitor) {
		super(modelName, serviceProvider, program, monitor);
		this.loader = loader;
	}

	public CustomLoadingAddressTableModel(String modelName, ServiceProvider serviceProvider,
			Program program, TableModelLoader<Address> loader, TaskMonitor monitor,
			boolean loadIncrementally) {
		super(modelName, serviceProvider, program, monitor, loadIncrementally);
		this.loader = loader;
	}

	@Override
	protected void doLoad(Accumulator<Address> accumulator, TaskMonitor monitor)
			throws CancelledException {
		loader.load(accumulator, monitor);
	}

}
