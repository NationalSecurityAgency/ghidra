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

import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;

/**
 * A simple object that holds an {@link AddressCorrelation} address range and then name of the 
 * correlation.s
 */
public class AddressCorrelationRange {

	private AddressRange range;
	private String correlatorName;

	public AddressCorrelationRange(AddressRange range, String correlatorName) {
		this.range = Objects.requireNonNull(range);
		this.correlatorName = Objects.requireNonNull(correlatorName);
	}

	public Address getMinAddress() {
		return range.getMinAddress();
	}

	public AddressRange getRange() {
		return range;
	}

	public String getCorrelatorName() {
		return correlatorName;
	}
}
