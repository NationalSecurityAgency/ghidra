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
package ghidra.app.merge.listing;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.AddressTranslationException;
import ghidra.program.util.AddressTranslator;

import java.util.HashMap;

/**
 * ExternalsAddressTranslator is a translator that can be used for merging external functions and
 * labels. <br>
 * Important: Before using this with ProgramMerge you must add all the address pairs that
 * will translate the external address space address from the source program to the address
 * in the destination program.
 */
public class ExternalsAddressTranslator implements AddressTranslator {

	protected Program destinationProgram;
	protected Program sourceProgram;
	HashMap<Address, Address> addressMap = new HashMap<Address, Address>(); // key = source, value = destination

	public ExternalsAddressTranslator(Program destinationProgram, Program sourceProgram) {
		this.destinationProgram = destinationProgram;
		this.sourceProgram = sourceProgram;
	}

	@Override
	public Program getDestinationProgram() {
		return destinationProgram;
	}

	@Override
	public Program getSourceProgram() {
		return sourceProgram;
	}

	public void setPair(Address destinationAddress, Address sourceAddress) {
		// Should this actually do a clear first, instead of the check and possible remove?
		if (destinationAddress != null) {
			addressMap.put(sourceAddress, destinationAddress);
		}
		else {
			addressMap.remove(sourceAddress);
		}
	}

	@Override
	public Address getAddress(Address sourceAddress) {
		Address destinationAddress = addressMap.get(sourceAddress);
		if (destinationAddress != null) {
			return destinationAddress;
		}
		throw new AddressTranslationException(
			"The specified source address never had an external address pair added to the translator.");
	}

	@Override
	public boolean isOneForOneTranslator() {
		return true;
	}

	@Override
	public AddressSet getAddressSet(AddressSetView sourceAddressSet) {
		if (sourceAddressSet == null) {
			return null;
		}
		if (sourceAddressSet.getNumAddresses() > 1) {
			throw new AddressTranslationException(
				"An external address translator can only handle a single address at a time, if that.");
		}
		AddressSet destinationSet = new AddressSet();
		if (sourceAddressSet.isEmpty()) {
			return destinationSet;
		}
		Address sourceAddress = sourceAddressSet.getMinAddress();
		Address destinationAddress = addressMap.get(sourceAddress);
		if (destinationAddress != null) {
			destinationSet.add(destinationAddress);
		}
		throw new AddressTranslationException(
			"The specified source address set never had an external address pair added to the translator.");
	}

	@Override
	public AddressRange getAddressRange(AddressRange sourceAddressRange)
			throws AddressTranslationException {
		if (sourceAddressRange == null) {
			return null;
		}
		if (sourceAddressRange.getLength() != 1) {
			throw new AddressTranslationException(
				"An external address translator can only handle a single address at a time, if that.");
		}
		Address sourceAddress = sourceAddressRange.getMinAddress();
		Address destinationAddress = addressMap.get(sourceAddress);
		if (destinationAddress != null) {
			return new AddressRangeImpl(destinationAddress, destinationAddress);
		}
		throw new AddressTranslationException(
			"The specified source address range never had an external address pair added to the translator.");
	}

}
