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

import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;

public class DefaultAddressTranslator implements AddressTranslator {

	protected Program destinationProgram;
	protected Program sourceProgram;

	public DefaultAddressTranslator(Program destinationProgram, Program sourceProgram) {
		this.destinationProgram = destinationProgram;
		this.sourceProgram = sourceProgram;
	}

	public Program getDestinationProgram() {
		return destinationProgram;
	}

	public Program getSourceProgram() {
		return sourceProgram;
	}

	public Address getAddress(Address sourceAddress) {
		return SimpleDiffUtility.getCompatibleAddress(sourceProgram, sourceAddress,
			destinationProgram);
	}

	public boolean isOneForOneTranslator() {
		return true;
	}

	public AddressSet getAddressSet(AddressSetView sourceAddressSet) {
		if (sourceAddressSet == null) {
			return null; // FIXME
		}
		return DiffUtility.getCompatibleAddressSet(sourceAddressSet, destinationProgram);
	}

	@Override
	public AddressRange getAddressRange(AddressRange sourceAddressRange)
			throws AddressTranslationException {
		return DiffUtility.getCompatibleAddressRange(sourceAddressRange, destinationProgram);
	}

}
