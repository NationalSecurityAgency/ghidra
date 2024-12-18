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
package ghidra.program.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.listing.Data;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class LinearDataAddressCorrelation implements AddressCorrelation {
	private final Data sourceData;
	private final Data destinationData;

	public LinearDataAddressCorrelation(Data sourceData, Data destinationData) {
		this.sourceData = sourceData;
		this.destinationData = destinationData;
	}

	@Override
	public AddressCorrelationRange getCorrelatedDestinationRange(Address sourceAddress,
			TaskMonitor monitor) throws CancelledException {
		long offset = sourceAddress.getOffset();
		long base = sourceData.getAddress().getOffset();
		long delta = offset - base;
		Address address = destinationData.getAddress().add(delta);
		AddressRangeImpl range = new AddressRangeImpl(address, address);
		return new AddressCorrelationRange(range, getName());
	}

	@Override
	public String getName() {
		return "LinearDataAddressCorrelation";
	}
}
