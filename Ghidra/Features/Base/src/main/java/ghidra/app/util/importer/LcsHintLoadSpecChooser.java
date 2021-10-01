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

import java.util.Collection;

import ghidra.app.util.opinion.*;
import ghidra.program.model.lang.*;
import ghidra.util.Msg;
import util.CollectionUtils;

/**
 * Chooses a {@link LoadSpec} for a {@link Loader} to use based on a provided {@link Language} and
 * {@link CompilerSpec}.
 */
public class LcsHintLoadSpecChooser implements LoadSpecChooser {
	private final LanguageID languageID;
	private final CompilerSpecID compilerSpecID;

	/**
	 * Creates a new {@link LcsHintLoadSpecChooser}.
	 * <p>
	 * NOTE: It is assumed that the given {@link Language} is valid and it supports the given 
	 * {@link CompilerSpec}.
	 * 
	 * @param language The {@link Language} to use (should not be null)
	 * @param compilerSpec The {@link CompilerSpec} to use (f null default compiler spec will be used)
	 */
	public LcsHintLoadSpecChooser(Language language, CompilerSpec compilerSpec) {
		this.languageID = language.getLanguageID();
		this.compilerSpecID =
			(compilerSpec == null) ? language.getDefaultCompilerSpec().getCompilerSpecID()
					: compilerSpec.getCompilerSpecID();
	}

	@Override
	public LoadSpec choose(LoaderMap loaderMap) {

		// Use the highest priority loader (it will be the first one)
		Loader loader = loaderMap.keySet().stream().findFirst().orElse(null);
		if (loader == null) {
			return null;
		}

		// Try to use a known LoadSpec that matches the desired language/compiler spec
		Collection<LoadSpec> loadSpecs = loaderMap.get(loader);
		for (LoadSpec loadSpec : loadSpecs) {
			// single loadSpec with null LCS pair may exist when no opinion was found
			LanguageCompilerSpecPair lcsPair = loadSpec.getLanguageCompilerSpec();
			if (lcsPair != null && lcsPair.languageID.equals(languageID) &&
				(compilerSpecID == null || lcsPair.compilerSpecID.equals(compilerSpecID))) {
				return loadSpec;
			}
		}

		// The desired language/compiler spec is not a defined LoadSpec, so we'll create a custom 
		// one. This could result in crazy results/analysis, but the point of this chooser is to do 
		// what we are told.
		LoadSpec anyLoadSpec = CollectionUtils.any(loadSpecs);
		LanguageCompilerSpecPair customLcsPair =
			new LanguageCompilerSpecPair(languageID, compilerSpecID);
		LoadSpec customLoadSpec =
			new LoadSpec(loader, anyLoadSpec.getDesiredImageBase(), customLcsPair, false);
		Msg.warn(this, "Using unknown opinion: " + loader.getName() + ", " + customLcsPair);
		return customLoadSpec;
	}
}
