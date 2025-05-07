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
package ghidra.app.decompiler.location;

import java.util.Objects;

import ghidra.app.decompiler.*;
import ghidra.framework.options.SaveState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.util.VariableLocFieldLocation;

/**
 * A location created when a function variable is clicked in the Decompiler.
 */
public class VariableDecompilerLocation extends VariableLocFieldLocation
		implements DecompilerLocation {

	private DecompilerLocationInfo info;

	public VariableDecompilerLocation(Program program, Address locationAddr, Variable var,
			DecompilerLocationInfo info) {
		super(program, locationAddr, var, 0);
		this.info = info;
	}

	public VariableDecompilerLocation() {
		// for restoring from xml
		info = new DecompilerLocationInfo();
	}

	@Override
	public Address getFunctionEntryPoint() {
		return info.getFunctionEntryPoint();
	}

	@Override
	public DecompileResults getDecompile() {
		return info.getDecompile();
	}

	@Override
	public ClangToken getToken() {
		return info.getToken();
	}

	@Override
	public String getTokenName() {
		return info.getTokenName();
	}

	@Override
	public int getLineNumber() {
		return info.getLineNumber();
	}

	@Override
	public int getCharPos() {
		return info.getCharPos();
	}

	@Override
	public void saveState(SaveState ss) {
		super.saveState(ss);
		info.saveState(ss);
	}

	@Override
	public void restoreState(Program p, SaveState ss) {
		super.restoreState(p, ss);
		info.restoreState(p, ss);
	}

	@Override
	public int hashCode() {
		int result = super.hashCode();
		result = info.hashCode();
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (this == obj) {
			return true;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}

		if (!super.equals(obj)) {
			return false;
		}

		VariableDecompilerLocation other = (VariableDecompilerLocation) obj;
		return Objects.equals(info, other.info);
	}
}
