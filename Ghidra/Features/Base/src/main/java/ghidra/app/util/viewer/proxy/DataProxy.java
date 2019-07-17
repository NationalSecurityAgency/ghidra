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
package ghidra.app.util.viewer.proxy;

import ghidra.app.util.viewer.listingpanel.ListingModel;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;

import java.util.ConcurrentModificationException;

/**
 * Stores information about a data item in a program such that the data item can 
 * be retrieved when needed.
 */
public class DataProxy extends ProxyObj<Data> {
	private Program program;
	private Data data;
	private Address addr;
	private int[] path;

	/**
	 * Construct a proxy for the given Data object.
	 * @param program the program containing the data object.
	 * @param data the Data object to proxy.
	 */
	public DataProxy(ListingModel model, Program program, Data data) {
		super(model);
		this.program = program;
		this.data = data;
		this.addr = data.getMinAddress();
		this.path = data.getComponentPath();
	}

	/**
	 * @see ghidra.app.util.viewer.proxy.ProxyObj#getObject()
	 */
	@Override
	public Data getObject() {
		if (data != null) {
			try {
				data.getMinAddress();
				return data;
			}
			catch (ConcurrentModificationException e) {
			}
		}
		data = program.getListing().getDataContaining(addr);
		if (data != null) {
			data = data.getComponent(path);
		}
		return data;
	}

}
