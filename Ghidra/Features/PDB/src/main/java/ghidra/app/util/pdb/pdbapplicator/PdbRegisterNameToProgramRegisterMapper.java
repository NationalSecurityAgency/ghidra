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
package ghidra.app.util.pdb.pdbapplicator;

import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Maps PDB register name to program {@link Register}.
 */
public class PdbRegisterNameToProgramRegisterMapper {

	// Only need to map names that are different (probably not counting case, as rsp and RSP
	// are equivalent.
	//@formatter:off
	private static final Map<String, String> REGISTER_NAME_MAP = Map.of(
		//"rsp", "RSP",
		"fbp", "RBP"
	);
	//@formatter:on

	private Program program;
	private Map<String, Register> pdbRegisterNameToRegisterMap;

	public PdbRegisterNameToProgramRegisterMapper(Program program) {
		this.program = program;
		pdbRegisterNameToRegisterMap = new HashMap<>();
	}

	Register getRegister(String pdbRegisterName) {
		Register register = pdbRegisterNameToRegisterMap.get(pdbRegisterName);
		if (register != null) {
			return register;
		}
		String registerName = REGISTER_NAME_MAP.get(pdbRegisterName);
		if (registerName == null) {
			registerName = pdbRegisterName;
		}
		register = program.getRegister(registerName);
		pdbRegisterNameToRegisterMap.put(pdbRegisterName, register);
		if (register == null) {
			Msg.info(this, "Program register not found for " + registerName);
		}
		return register;
	}

}
