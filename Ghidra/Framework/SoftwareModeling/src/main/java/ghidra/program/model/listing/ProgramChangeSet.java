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
package ghidra.program.model.listing;

import ghidra.program.model.address.AddressSetCollection;

/**
 * Interface for a Program Change set.  Objects that implements this interface track
 * various change information on a program.
 */
public interface ProgramChangeSet
		extends DomainObjectChangeSet, AddressChangeSet, RegisterChangeSet, DataTypeChangeSet,
		ProgramTreeChangeSet, SymbolChangeSet, FunctionTagChangeSet {

	/**
	 * Gets an AddressSetCollection which contains the addressSets that track all the addresses
	 * where changes have occurred since the last save.
	 * @return AddressSetCollection containing all addresses that changed since the last save.
	 */
	AddressSetCollection getAddressSetCollectionSinceLastSave();

	/**
	 * Gets an AddressSetCollection which contains the addressSets that track all the addresses
	 * where changes have occurred since the file was checked out. If the file is not versioned,
	 * this AddressSetCollection will be empty.
	 * @return AddressSetCollection containing all addresses that changed since the program was checked out.
	 */
	AddressSetCollection getAddressSetCollectionSinceCheckout();

}
