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
package ghidra.feature.vt.api.db;

import ghidra.program.model.address.Address;

/**
 * A simple object that holds information about a match that has been deleted from the database.
 */
public class DeletedMatch {

	private final Address sourceAddress;
	private final Address destinationAddress;

	DeletedMatch(Address sourceAddress, Address destinationAddress) {
		this.sourceAddress = sourceAddress;
		this.destinationAddress = destinationAddress;
	}

	public Address getSourceAddress() {
		return sourceAddress;
	}

	public Address getDestinationAddress() {
		return destinationAddress;
	}
}
