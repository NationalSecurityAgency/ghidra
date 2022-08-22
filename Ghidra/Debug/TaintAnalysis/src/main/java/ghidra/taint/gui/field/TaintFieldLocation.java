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
package ghidra.taint.gui.field;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.CodeUnitLocation;
import ghidra.program.util.ProgramLocation;

/**
 * This is a {@link ProgramLocation} for when the user's cursor is in our "Taint" field
 * 
 * <p>
 * I used the "sample" module's {@code EntropyFieldLocation} for reference.
 */
public class TaintFieldLocation extends CodeUnitLocation {
	public TaintFieldLocation(Program program, Address address, int charOffset) {
		super(program, address, 0, 0, charOffset);
	}

	// Need default for XML restore
	public TaintFieldLocation() {
	}
}
