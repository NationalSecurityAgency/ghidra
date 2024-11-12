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
package ghidra.plugin.importer;

import ghidra.program.model.lang.LanguageCompilerSpecPair;

public class LcsSelectionEvent {

	public enum Type {
		/** A language was selected in the UI */
		SELECTED,

		/** A language was picked (e.g., double-clicked) in the UI */
		PICKED
	}

	private final LanguageCompilerSpecPair lcs;
	private final Type type;

	public LcsSelectionEvent(LanguageCompilerSpecPair selection, Type type) {
		this.lcs = selection;
		this.type = type;
	}

	public LanguageCompilerSpecPair getLcs() {
		return lcs;
	}

	public Type getType() {
		return type;
	}

	@Override
	public String toString() {
		return "LSE{" + lcs + "}";
	}
}
