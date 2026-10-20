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

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * Represents the '[more]' text used by the label field factory.
 */
public class MoreLabelFieldLocation extends CodeUnitLocation {

	public static final String MORE_LABELS_STRING = "[more]";

	public MoreLabelFieldLocation() {
		// for serialization
	}

	public MoreLabelFieldLocation(Program p, Address addr, int row, int charOffset) {
		super(p, addr, row, 0, charOffset);
	}

	@Override
	public String toString() {
		return MORE_LABELS_STRING;
	}
}
