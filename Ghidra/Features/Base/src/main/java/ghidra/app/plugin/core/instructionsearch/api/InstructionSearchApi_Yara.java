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
package ghidra.app.plugin.core.instructionsearch.api;

import ghidra.app.plugin.core.instructionsearch.InstructionSearchApi;
import ghidra.app.plugin.core.instructionsearch.model.MaskSettings;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.InvalidInputException;

/**
 * Extends the {@link InstructionSearchApi} for YARA users.
 *
 */
public class InstructionSearchApi_Yara extends InstructionSearchApi {

	/**
	 * Returns a YARA-formatted string representing the instructions in the address range
	 * provided, for the given program.
	 * 
	 * @param program the program to search
	 * @param addressRange the set of bytes to search for
	 * @return
	 * @throws InvalidInputException 
	 */
	public String getYaraString(Program program, AddressRange addressRange)
			throws InvalidInputException {
		return toYaraFormat(this.getHexSearchString(program, addressRange));
	}

	/**
	 * Returns a YARA-formatted string representing the instructions in the address range
	 * provided, for the given program, with maskings. 
	 * 
	 * @param program the program to search
	 * @param addressRange the set of bytes to search for
	 * @return
	 * @throws InvalidInputException 
	 */
	public String getYaraString(Program program, AddressRange addressRange,
			MaskSettings maskSettings) throws InvalidInputException {
		return toYaraFormat(this.getHexSearchString(program, addressRange, maskSettings));
	}

	/*********************************************************************************************
	 * PRIVATE METHODS
	 ********************************************************************************************/

	/**
	 * Converts a hex string with '.' as wildcard characters to one that YARA understands ('?').
	 * Also makes sure all characters are uppercase.
	 * 
	 * @param hexString
	 * @return
	 */
	private String toYaraFormat(String hexString) {
		return hexString.replaceAll("\\.", "?").toUpperCase();
	}
}
