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

import java.util.Arrays;

/**
 * ProgramLocation for the Register Field.
 * 
 * 
 *
 */
public class RegisterFieldLocation extends ProgramLocation {

	private String[] registerNames;
	private String[] registerStrings;

	//
	public RegisterFieldLocation(Program program, Address addr, String[] registerNames,
			String[] registerStrings, int row, int charOffset) {
		super(program, addr, addr, null, null, row, 0, charOffset);
		this.registerNames = registerNames;
		this.registerStrings = registerStrings;
	}

	/**
	 * Default constructor 
	 */
	public RegisterFieldLocation() {
	}

	/**
	 * Get the register strings.
	 */
	public String[] getRegisterStrings() {
		return registerStrings;
	}

	public Register getRegister() {
		if (getRow() < registerNames.length) {
			return program.getRegister(registerNames[getRow()]);
		}
		return null;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + Arrays.hashCode(registerNames);
		result = prime * result + Arrays.hashCode(registerStrings);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!super.equals(obj))
			return false;
		if (getClass() != obj.getClass())
			return false;
		RegisterFieldLocation other = (RegisterFieldLocation) obj;
		if (!Arrays.equals(registerNames, other.registerNames))
			return false;
		if (!Arrays.equals(registerStrings, other.registerStrings))
			return false;
		return true;
	}

	@Override
	public void saveState(SaveState obj) {
		super.saveState(obj);
		obj.putStrings("_Register_Names", registerNames);
		obj.putStrings("_Register_Strings", registerStrings);
	}

	@Override
	public void restoreState(Program p, SaveState obj) {
		super.restoreState(p, obj);
		registerNames = obj.getStrings("_Register_Names", new String[0]);
		registerStrings = obj.getStrings("_Register_Strings", new String[0]);
	}
}
