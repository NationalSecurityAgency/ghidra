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
package ghidra.examples2;

import ghidra.program.model.address.Address;

public class SearchResults {

	private Address address;
	private String displayValue;

	public SearchResults(Address address, String displayValue) {
		this.address = address;
		this.displayValue = displayValue;

	}

	public String getDisplayValue() {
		return displayValue;
	}

	public Address getAddress() {
		return address;
	}

}
