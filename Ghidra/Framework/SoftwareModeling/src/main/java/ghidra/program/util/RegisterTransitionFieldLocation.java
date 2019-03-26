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
/**
 * 
 */
package ghidra.program.util;

import ghidra.framework.options.SaveState;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;

/**
 * ProgramLocation for the Register Field.
 * 
 * 
 *
 */
public class RegisterTransitionFieldLocation extends ProgramLocation {

	private String[] registerNames;

	public RegisterTransitionFieldLocation(Program program, Address addr, String[] registerNames,
			int row, int column) {
		super(program, addr, addr, null, null, row, 0, column);
		this.registerNames = registerNames;
	}

	/**
	 * Default constructor 
	 */
	public RegisterTransitionFieldLocation() {
	}

	public Register getRegister() {
		if (getRow() < registerNames.length) {
			return program.getRegister(registerNames[getRow()]);
		}
		return null;
	}

	@Override
	public void restoreState(Program p, SaveState obj) {
		super.restoreState(p, obj);
		registerNames = obj.getStrings("_Register_Names", new String[0]);
	}

	@Override
	public void saveState(SaveState obj) {
		super.saveState(obj);
		obj.putStrings("Register_Names", registerNames);
	}
}
