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
package ghidra.program.model.listing;

import ghidra.program.model.symbol.Symbol;

public class LabelString {

	public enum LabelType {
		CODE_LABEL, VARIABLE, EXTERNAL
	}

	private final String label;
	private final LabelType type;
	private Symbol symbol;

	public LabelString(String label, LabelType type) {
		this.label = label;
		this.type = type;
	}

	public LabelString(String label, Symbol symbol, LabelType type) {
		this.label = label;
		this.symbol = symbol;
		this.type = type;
	}

	public Symbol getSymbol() {
		return symbol;
	}

	@Override
	public String toString() {
		return label;
	}

	public LabelType getLabelType() {
		return type;
	}

}
