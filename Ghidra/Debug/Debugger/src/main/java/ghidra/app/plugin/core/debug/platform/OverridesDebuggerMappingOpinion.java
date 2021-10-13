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
package ghidra.app.plugin.core.debug.platform;

import java.util.Set;
import java.util.stream.Collectors;

import ghidra.app.plugin.core.debug.mapping.*;
import ghidra.dbg.target.*;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;

/**
 * An "opinion" which offers every known language, but with only default mapping logic.
 * 
 * <p>
 * Mileage will vary greatly, but some mileage is better than none.
 */
public class OverridesDebuggerMappingOpinion implements DebuggerMappingOpinion {

	/**
	 * An opinion-specific offer class so that offers can be recognized in unit testing
	 */
	protected static class OverrideOffer extends DefaultDebuggerMappingOffer {
		public OverrideOffer(TargetObject target, int confidence, String description,
				LanguageCompilerSpecPair lcsp) {
			super(target, confidence, description, lcsp.languageID, lcsp.compilerSpecID, Set.of());
		}
	}

	protected DebuggerMappingOffer offerForLanguageAndCSpec(TargetObject target, Endian endian,
			LanguageCompilerSpecPair lcsp) {
		try {
			return new OverrideOffer(target,
				endian == lcsp.getLanguageDescription().getEndian() ? -10 : -20,
				"Override to " + lcsp, lcsp);
		}
		catch (LanguageNotFoundException e) {
			throw new AssertionError(e);
		}
	}

	@Override
	public Set<DebuggerMappingOffer> offersForEnv(TargetEnvironment env, TargetProcess process,
			boolean includeOverrides) {
		if (!includeOverrides) {
			return Set.of();
		}
		Endian endian = DebuggerMappingOpinion.getEndian(env);
		LanguageService langServ = DefaultLanguageService.getLanguageService();
		return langServ.getLanguageCompilerSpecPairs(
			// ALL THE SPECS!!!
			new LanguageCompilerSpecQuery(null, null, null, null, null))
				.stream()
				.map(lcsp -> offerForLanguageAndCSpec(process, endian, lcsp))
				.collect(Collectors.toSet());
	}
}
