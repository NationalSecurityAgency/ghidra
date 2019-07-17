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
package ghidra.app.decompiler;

import java.util.Objects;

import ghidra.framework.options.SaveState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

public class DecompilerLocation extends ProgramLocation {
	private Address functionEntryPoint;
	private DecompileResults results;
	private ClangToken token;
	private String tokenName;
	private int lineNumber;
	private int charPos;

	public DecompilerLocation(Program program, Address address, Address functionEntryPoint,
			DecompileResults results, ClangToken token, int lineNumber, int charPos) {
		super(program, address);
		this.functionEntryPoint = functionEntryPoint;
		this.results = results;
		this.token = token;
		this.tokenName = token.getText();
		this.lineNumber = lineNumber;
		this.charPos = charPos;
	}

	/**
	 * Default constructor required for restoring a program location from XML.
	 */
	public DecompilerLocation() {
	}

	public Address getFunctionEntryPoint() {
		return functionEntryPoint;
	}

	/**
	 * Results from the decompilation
	 * 
	 * @return C-AST, DFG, and CFG object. null if there are no results attached to this location
	 */
	public DecompileResults getDecompile() {
		return results;
	}

	/**
	 * C text token at the current cursor location
	 * 
	 * @return token at this location, could be null if there are no decompiler results
	 */
	public ClangToken getToken() {
		return token;
	}

	public String getTokenName() {
		return tokenName;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + charPos;
		result =
			prime * result + ((functionEntryPoint == null) ? 0 : functionEntryPoint.hashCode());
		result = prime * result + lineNumber;
		result = prime * result + ((tokenName == null) ? 0 : tokenName.hashCode());
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

		DecompilerLocation other = (DecompilerLocation) obj;
		if (charPos != other.charPos) {
			return false;
		}

		if (lineNumber != other.lineNumber) {
			return false;
		}

		if (!Objects.equals(functionEntryPoint, other.functionEntryPoint)) {
			return false;
		}

		if (!Objects.equals(tokenName, other.tokenName)) {
			return false;
		}
		return true;
	}

	@Override
	public void saveState(SaveState saveState) {
		super.saveState(saveState);
		saveState.putString("_FUNCTION_ENTRY", functionEntryPoint.toString());
		saveState.putString("_TOKEN_TEXT", tokenName);
		saveState.putInt("_LINE_NUM", lineNumber);
		saveState.putInt("_CHAR_POS", charPos);
	}

	@Override
	public void restoreState(Program program1, SaveState obj) {
		super.restoreState(program1, obj);
		String addrStr = obj.getString("_FUNCTION_ENTRY", "0");
		functionEntryPoint = program1.parseAddress(addrStr)[0];
		tokenName = obj.getString("_TOKEN_TEXT", "");
		lineNumber = obj.getInt("_LINE_NUM", 0);
		charPos = obj.getInt("_CHAR_POS", 0);
	}

	public int getLineNumber() {
		return lineNumber;
	}

	public int getCharPos() {
		return charPos;
	}

	@Override
	public String toString() {
		StringBuilder buf = new StringBuilder();
		buf.append(getClass().getSimpleName());
		buf.append('@');
		buf.append(addr.toString());
		buf.append(", line=");
		buf.append(lineNumber);
		buf.append(", character=");
		buf.append(charPos);
		buf.append(", token=");
		buf.append(tokenName);
		return buf.toString();
	}
}
