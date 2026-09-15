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
package ghidra.plugins.importer.batch;

import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.program.model.lang.LanguageCompilerSpecPair;

/**
 * Similar to a {@link LoadSpec}, but not associated with a {@link Loader}.
 * <p>
 * This has the same information as a {@link LoadSpec}, but for all the members of a 
 * {@link BatchGroup}.
 * 
 * @param lcsPair The language/compiler spec ID
 * @param preferred true if this {@link BatchGroupLoadSpec} is preferred; otherwise, false
 */
public record BatchGroupLoadSpec(LanguageCompilerSpecPair lcsPair, boolean preferred)
		implements Comparable<BatchGroupLoadSpec> {

	public BatchGroupLoadSpec(LoadSpec loadSpec) {
		this(loadSpec.getLanguageCompilerSpec(), loadSpec.isPreferred());
	}

	@Override
	public String toString() {
		return (lcsPair != null ? lcsPair.toString() : "none") + (preferred ? "*" : "");
	}

	public boolean matches(LoadSpec loadSpec) {
		return (loadSpec.getLanguageCompilerSpec() == lcsPair) ||
			(loadSpec.getLanguageCompilerSpec() != null &&
				loadSpec.getLanguageCompilerSpec().equals(lcsPair));
	}

	@Override
	public int compareTo(BatchGroupLoadSpec o) {
		String s1 = this.toString();
		String s2 = o.toString();
		return s1.compareTo(s2);
	}
}
