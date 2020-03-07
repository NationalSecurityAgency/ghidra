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
package ghidra.app.util.viewer.util;

import java.math.BigInteger;

import docking.widgets.fieldpanel.listener.IndexMapper;
import ghidra.program.model.address.Address;

/** Implementation of IndexMapper that uses an old and new AddressIndexMap to map indexes 
 *  when the AddressIndexMap changes. 
 */
public class AddressBasedIndexMapper implements IndexMapper {

	private AddressIndexMap from;
	private AddressIndexMap to;

	public AddressBasedIndexMapper(AddressIndexMap from, AddressIndexMap to) {
		this.from = from;
		this.to = to;
	}

	@Override
	public BigInteger map(BigInteger value) {
		Address address = from.getAddress(value);
		if (address == null) {
			return BigInteger.ZERO;
		}
		BigInteger mapped = to.getIndex(address);
		return mapped != null ? mapped : BigInteger.ZERO;
	}
}
