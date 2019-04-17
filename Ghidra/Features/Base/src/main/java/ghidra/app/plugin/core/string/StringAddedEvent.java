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

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.util.string.FoundString;
import ghidra.program.util.string.FoundString.DefinedState;

public class StringAddedEvent extends StringEvent {

	public StringAddedEvent(DataType stringDataType, Address address, int length) {
		super(stringDataType, address, length);
	}

	@Override
	public void process(StringTableModel model, StringTableOptions options) {
		// first attempt to find the corresponding entry quickly
		FoundString newString = new FoundString(address, length, stringDataType);
		int row = model.getRowIndex(newString);

		FoundString existingString = null;
		if (row >= 0) {
			existingString = model.getRowObject(row);
			if (!existingString.getAddress().equals(address)) {
				existingString = null;
			}
		}
		if (existingString == null) {
			existingString = findRowSlowWay(model);
		}

		if (existingString == null) {
			if (options.includeDefinedStrings()) {
				newString.setDefinedState(DefinedState.DEFINED);
				model.addObject(newString);
			}
			return;
		}

		updateMatch(existingString, newString);

		if (existingString.isDefined() && !options.includeDefinedStrings()) {
			model.removeObject(existingString);
		}
		else if (existingString.isPartiallyDefined() && !options.includePartiallyDefinedStrings()) {
			model.removeObject(existingString);
		}
		else {
			model.updateObject(existingString);
		}

	}

	private void updateMatch(FoundString existingString, FoundString newString) {
		Address existingAddr = existingString.getAddress();
		Address newAddr = newString.getAddress();

		if (existingAddr.equals(newAddr) && existingString.getLength() <= newString.getLength()) {
			existingString.setDefinedState(DefinedState.DEFINED);
			return;
		}

		Address existingEndAddr = existingString.getEndAddress();
		Address newEndAddr = newString.getEndAddress();

		Address minAddress = getMinAddress(existingAddr, newAddr);
		Address maxAddress = getMaxAddress(existingEndAddr, newEndAddr);
		length = (int) maxAddress.subtract(minAddress) + 1;

		existingString.setAddress(minAddress);
		existingString.setLength(length);
		existingString.setDefinedState(DefinedState.PARTIALLY_DEFINED);
	}

}
