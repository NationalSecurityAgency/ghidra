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

public class DecompilerLocationInfo {

	private Address entryPoint;
	private DecompileResults results;
	private ClangToken token;
	private String tokenName;
	private int lineNumber;
	private int charPos;

	public DecompilerLocationInfo(Address entryPoint, DecompileResults results,
			ClangToken token, int lineNumber, int charPos) {
		this.entryPoint = entryPoint;
		this.results = results;
		this.token = token;
		this.tokenName = token.getText();
		this.lineNumber = lineNumber;
		this.charPos = charPos;
	}

	/**
	 * Default constructor required for restoring a program location from XML.
	 */
	public DecompilerLocationInfo() {
	}

	public Address getFunctionEntryPoint() {
		return entryPoint;
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

	public int getLineNumber() {
		return lineNumber;
	}

	public int getCharPos() {
		return charPos;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + charPos;
		result =
			prime * result + ((entryPoint == null) ? 0 : entryPoint.hashCode());
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

		DecompilerLocationInfo other = (DecompilerLocationInfo) obj;
		if (charPos != other.charPos) {
			return false;
		}

		if (lineNumber != other.lineNumber) {
			return false;
		}

		if (!Objects.equals(entryPoint, other.entryPoint)) {
			return false;
		}

		if (!Objects.equals(tokenName, other.tokenName)) {
			return false;
		}
		return true;
	}

	public void saveState(SaveState saveState) {
		saveState.putString("_FUNCTION_ENTRY", entryPoint.toString());
		saveState.putString("_TOKEN_TEXT", tokenName);
		saveState.putInt("_LINE_NUM", lineNumber);
		saveState.putInt("_CHAR_POS", charPos);
	}

	public void restoreState(Program program1, SaveState obj) {
		String addrStr = obj.getString("_FUNCTION_ENTRY", "0");
		entryPoint = program1.parseAddress(addrStr)[0];
		tokenName = obj.getString("_TOKEN_TEXT", "");
		lineNumber = obj.getInt("_LINE_NUM", 0);
		charPos = obj.getInt("_CHAR_POS", 0);
	}

	@Override
	public String toString() {
		StringBuilder buf = new StringBuilder();
		buf.append(getClass().getSimpleName());
		buf.append(", line=");
		buf.append(lineNumber);
		buf.append(", character=");
		buf.append(charPos);
		buf.append(", token=");
		buf.append(tokenName);
		return buf.toString();
	}
}
