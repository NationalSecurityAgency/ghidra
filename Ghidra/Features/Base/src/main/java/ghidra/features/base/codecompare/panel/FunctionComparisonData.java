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

import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.FunctionSignatureFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HTMLUtilities;

/**
 * ComparisonData for a function
 */
public class FunctionComparisonData implements ComparisonData {

	private final Function function;

	public FunctionComparisonData(Function function) {
		this.function = Objects.requireNonNull(function);
	}

	@Override
	public Function getFunction() {
		return function;
	}

	@Override
	public AddressSetView getAddressSet() {
		if (function.isExternal()) {
			return new AddressSet(function.getEntryPoint(), function.getEntryPoint());
		}
		return function.getBody();
	}

	@Override
	public Program getProgram() {
		return function.getProgram();
	}

	@Override
	public String getDescription() {
		StringBuffer buf = new StringBuffer();
		String padStr = HTMLUtilities.spaces(4);
		buf.append(padStr);

		String functionStr = HTMLUtilities.friendlyEncodeHTML(function.getName(true) + "()");
		String specialFunctionStr = HTMLUtilities.bold(functionStr);
		buf.append(specialFunctionStr);
		Program program = function.getProgram();
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

	@Override
	public String getShortDescription() {
		return function.getName();
	}

	@Override
	public boolean isEmpty() {
		return false;
	}

	@Override
	public ProgramLocation getInitialLocation() {
		return new FunctionSignatureFieldLocation(function.getProgram(), function.getEntryPoint());
	}

}
