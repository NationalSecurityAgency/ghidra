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
package ghidra.app.util.importer;

import ghidra.app.util.opinion.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecID;

/**
 * Chooses a {@link LoadSpec} for a {@link Loader} to use based on a provided {@link CompilerSpec}.
 */
public class CsHintLoadSpecChooser implements LoadSpecChooser {
	private final CompilerSpecID compilerSpecID;

	/**
	 * Creates a new {@link CsHintLoadSpecChooser}
	 * 
	 * @param compilerSpecID The {@link CompilerSpecID} to use (should not be null)
	 */
	public CsHintLoadSpecChooser(CompilerSpecID compilerSpecID) {
		this.compilerSpecID = compilerSpecID;
	}

	/**
	 * Creates a new {@link CsHintLoadSpecChooser}
	 * 
	 * @param compilerSpecID The {@link CompilerSpecID} to use (should not be null)
	 */
	public CsHintLoadSpecChooser(String compilerSpecID) {
		this(new CompilerSpecID(compilerSpecID));
	}

	@Override
	public LoadSpec choose(LoaderMap loaderMap) {

		return loaderMap.values()
				.stream()
				.flatMap(loadSpec -> loadSpec.stream())
				.filter(
					loadSpec -> loadSpec != null && loadSpec.getLanguageCompilerSpec() != null &&
						loadSpec.getLanguageCompilerSpec().compilerSpecID.equals(compilerSpecID))
				.findFirst()
				.orElse(null);
	}
}
