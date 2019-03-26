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
package ghidra.feature.vt.api.stringable;

import ghidra.feature.vt.api.util.Stringable;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.SystemUtilities;

import java.util.StringTokenizer;

public class SymbolStringable extends Stringable {

	public static final String SHORT_NAME = "SYM";

	private String symbolName;
	private SourceType sourceType;

	public SymbolStringable() {
		this(null, null); // deserialization constructor
	}

	public SymbolStringable(String symbolName, SourceType symbolType) {
		super(SHORT_NAME);
		this.symbolName = symbolName;
		this.sourceType = symbolType;
	}

	@Override
	public String getDisplayString() {
//	    return symbolName + "(" + sourceType.name() + ")";
		return (symbolName != null) ? symbolName : "";
	}

	@Override
	protected String doConvertToString(Program program) {
		return symbolName + DELIMITER + sourceType.name();
	}

	@Override
	protected void doRestoreFromString(String string, Program program) {
		StringTokenizer tokenizzy = new StringTokenizer(string, DELIMITER);
		symbolName = tokenizzy.nextToken();
		String sourceName = tokenizzy.nextToken();
		sourceType = SourceType.valueOf(sourceName);
	}

	public String getSymbolName() {
		return symbolName;
	}

	public SourceType getSourceType() {
		return sourceType;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((sourceType == null) ? 0 : sourceType.hashCode());
		result = prime * result + ((symbolName == null) ? 0 : symbolName.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if ((obj == null) || (getClass() != obj.getClass())) {
			return false;
		}
		SymbolStringable other = (SymbolStringable) obj;

		return SystemUtilities.isEqual(symbolName, other.symbolName) &&
			sourceType == other.sourceType;
	}

}
