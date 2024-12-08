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

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.HTMLUtilities;

/**
 * ComparisonData for a generic set of addresses.
 */
public class AddressSetComparisonData implements ComparisonData {

	private Program program;
	private AddressSetView addresses;

	public AddressSetComparisonData(Program program, AddressSetView addresses) {
		this.program = Objects.requireNonNull(program);
		this.addresses = Objects.requireNonNull(addresses);
	}

	@Override
	public Function getFunction() {
		return null;
	}

	@Override
	public AddressSetView getAddressSet() {
		return addresses;
	}

	@Override
	public Program getProgram() {
		return program;
	}

	@Override
	public String getShortDescription() {
		Address minAddress = addresses.getMinAddress();
		Address maxAddress = addresses.getMinAddress();
		if (minAddress == null) {
			return "Empty";
		}
		return minAddress + ":" + maxAddress;
	}

	@Override
	public String getDescription() {
		StringBuffer buf = new StringBuffer();
		String padStr = HTMLUtilities.spaces(4);
		buf.append(padStr);
		String programStr = HTMLUtilities.friendlyEncodeHTML(program.getDomainFile().getPathname());
		String specialProgramStr = HTMLUtilities.colorString(FG_COLOR_TITLE, programStr);
		buf.append(specialProgramStr);
		buf.append(padStr);
		return HTMLUtilities.wrapAsHTML(buf.toString());
	}

	@Override
	public boolean isEmpty() {
		return addresses.isEmpty();
	}
}
