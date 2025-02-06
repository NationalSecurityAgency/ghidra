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
package ghidra.features.base.codecompare.panel;

import java.util.Objects;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HTMLUtilities;

/**
 * ComparisonData for a Data object
 */
public class DataComparisonData implements ComparisonData {

	private final Data data;
	private final AddressSet addresses;

	public DataComparisonData(Data data, int otherLength) {
		this.data = Objects.requireNonNull(data);
		int size = Math.max(data.getLength(), otherLength);
		this.addresses = new AddressSet(data.getMinAddress(), getEndAddress(size));
	}

	@Override
	public AddressSetView getAddressSet() {
		return addresses;
	}

	@Override
	public Program getProgram() {
		return data.getProgram();
	}

	@Override
	public Function getFunction() {
		return null;
	}

	@Override
	public boolean isEmpty() {
		return false;
	}

	@Override
	public String getShortDescription() {
		return data.getDataType().getName();
	}

	@Override
	public String getDescription() {
		StringBuffer buf = new StringBuffer();
		String padStr = HTMLUtilities.spaces(4);
		buf.append(padStr);

		String dataLabel = data.getLabel();
		if (dataLabel == null) { // If we can't get a label for the data then use the address .
			Address address = data.getAddress();
			dataLabel = address.toString();
		}
		String dataStr = HTMLUtilities.friendlyEncodeHTML(dataLabel);
		String specialDataStr = HTMLUtilities.bold(dataStr);
		buf.append(specialDataStr);

		Program program = data.getProgram();
		if (program != null) {
			buf.append(" in ");

			String programStr =
				HTMLUtilities.friendlyEncodeHTML(program.getDomainFile().getPathname());
			String specialProgramStr = HTMLUtilities.colorString(FG_COLOR_TITLE, programStr);
			buf.append(specialProgramStr);
			buf.append(padStr);
		}
		return HTMLUtilities.wrapAsHTML(buf.toString());
	}

	private Address getEndAddress(int size) {
		Address minAddress = data.getMinAddress();
		if (minAddress.isExternalAddress()) {
			return minAddress; // Begin and end address are same for external data.
		}
		MemoryBlock block = data.getProgram().getMemory().getBlock(minAddress);
		Address blockEnd = block.getEnd();
		Address endAddress;
		try {
			endAddress = minAddress.add(size);
			if (endAddress.compareTo(blockEnd) > 0) {
				endAddress = blockEnd;
			}
		}
		catch (AddressOutOfBoundsException e) {
			endAddress = blockEnd;
		}
		return endAddress;
	}

	@Override
	public ProgramLocation getInitialLocation() {
		return new ProgramLocation(data.getProgram(), data.getMinAddress());
	}
}
