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
package ghidra.feature.fid.hash;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;

/**
 * Calculates the function extent by the function body; i.e. what's saved
 * in the database as the body, which could be totally wrong (but then
 * again, so could we, if we try to determine it ourselves).
 *
 */
public class FunctionBodyFunctionExtentGenerator implements FunctionExtentGenerator {
	@Override
	public List<CodeUnit> calculateExtent(Function func) {
		if (func == null) {
			return List.of();
		}
		final AddressSetView body = func.getBody();
		if (body.isEmpty()) {
			return List.of();
		}
		ArrayList<CodeUnit> units = new ArrayList<CodeUnit>();

		final Program program = func.getProgram();
		final Listing listing = program.getListing();

		InstructionIterator codeUnitIterator = listing.getInstructions(body, true);
		for (Instruction codeUnit : codeUnitIterator) {
			units.add(codeUnit);
		}

		return units;
	}
}
