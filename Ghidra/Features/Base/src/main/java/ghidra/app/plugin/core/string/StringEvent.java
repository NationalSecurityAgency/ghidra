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
package ghidra.app.plugin.core.string;

import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.util.string.FoundString;

public abstract class StringEvent {

	protected DataType stringDataType;
	protected Address address;
	protected int length;

	protected StringEvent(DataType stringDataType, Address address, int length) {
		this.stringDataType = stringDataType;
		this.address = address;
		this.length = length;

	}

	public abstract void process(StringTableModel model, StringTableOptions options);

	protected FoundString findRowSlowWay(StringTableModel model) {
		List<FoundString> modelData = model.getModelData();
		for (int row = 0; row < modelData.size(); row++) {
			FoundString string = modelData.get(row);
			if (overlaps(string)) {
				return string;
			}
		}
		return null;
	}

	public Address getMaxAddress(Address addr1, Address addr2) {
		if (addr1.compareTo(addr2) > 0) {
			return addr1;
		}
		return addr2;
	}

	public Address getMinAddress(Address addr1, Address addr2) {
		if (addr1.compareTo(addr2) < 0) {
			return addr1;
		}
		return addr2;
	}

	protected boolean overlaps(FoundString string) {
		Address otherAddress = string.getAddress();
		int result = address.compareTo(otherAddress);
		if (result == 0) {
			return true;
		}
		if (result < 0) {
			return subtract(otherAddress, address) < length;
		}
		return subtract(address, otherAddress) < string.getLength();
	}

	private int subtract(Address bigAddress, Address smallAddress) {
		if (bigAddress.getAddressSpace() != smallAddress.getAddressSpace()) {
			return Integer.MAX_VALUE;
		}
		long diff = bigAddress.subtract(smallAddress);
		if (diff > Integer.MAX_VALUE) {
			return Integer.MAX_VALUE;
		}
		return (int) diff;
	}

}
