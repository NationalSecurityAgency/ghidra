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

import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

public class EmptyComparisonData implements ComparisonData {

	@Override
	public Function getFunction() {
		return null;
	}

	@Override
	public AddressSetView getAddressSet() {
		return new AddressSet();
	}

	@Override
	public Program getProgram() {
		return null;
	}

	@Override
	public String getDescription() {
		return "No Comparison Data";
	}

	@Override
	public String getShortDescription() {
		return "Empty";
	}

	@Override
	public boolean isEmpty() {
		return true;
	}

	@Override
	public ProgramLocation getInitialLocation() {
		return null;
	}
}
