/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.merge;

import ghidra.app.util.viewer.multilisting.AddressTranslator;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

import java.util.HashMap;
import java.util.Map;

public class ProgramSpecificAddressTranslator implements AddressTranslator {

	private Map<Program, Address> map = new HashMap<Program, Address>();

	@Override
	public Address translate(Address address, Program primaryProgram, Program program) {
		return map.get(program);
	}

	public void addProgramAddress(Program program, Address address) {
		map.put(program, address);
	}
}
