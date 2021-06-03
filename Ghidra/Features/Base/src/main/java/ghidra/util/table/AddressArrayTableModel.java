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
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This table model of addresses is used when you already have an
 * Address array built. 
 * <p>
 * If you need to compute the address array, then you should
 * extend {@link AddressPreviewTableModel} and override the 
 * {@link AddressPreviewTableModel#doLoad(Accumulator, TaskMonitor)
 * doLoad(Accumulator&lt;Address&gt; accumulator, TaskMonitor monitor)}
 *  method which will be called in a dedicated thread.
 *  <p>
 *  Alternatively, you can create an instance of the {@link CustomLoadingAddressTableModel},
 *  supplying your own loading via the {@link TableModelLoader}.
 */
public class AddressArrayTableModel extends AddressPreviewTableModel {

	private Address[] addrs;

	/**
	 * Constructor. 
	 * 
	 * @param title title of the query
	 * @param serviceProvider from which to get services
	 * @param prog program 
	 * @param addrs array of addresses in the model
	 * @param monitor monitor that is used to show progress; may be null
	 */
	public AddressArrayTableModel(String title, ServiceProvider serviceProvider, Program prog,
			Address[] addrs, TaskMonitor monitor) {
		super(title, serviceProvider, prog, monitor);
		this.addrs = addrs;
	}

	/**
	 * Constructor.
	 * 
	 * @param title title of the query
	 * @param serviceProvider from which to get services
	 * @param prog program 
	 * @param addrs array of addresses in the model
	 */
	public AddressArrayTableModel(String title, ServiceProvider serviceProvider, Program prog,
			Address[] addrs) {
		this(title, serviceProvider, prog, addrs, null);
	}

	@Override
	protected void doLoad(Accumulator<Address> accumulator, TaskMonitor monitor)
			throws CancelledException {
		for (Address element : addrs) {
			accumulator.add(element);
		}
	}

	public void setAddresses(Address[] addresses) {
		this.addrs = addresses;
		reload();
		fireTableDataChanged();
	}
}
