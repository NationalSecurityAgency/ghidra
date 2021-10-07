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
package ghidra.app.plugin.core.debug.service.model;

import java.util.Set;

import ghidra.app.plugin.core.debug.mapping.*;
import ghidra.dbg.target.TargetEnvironment;
import ghidra.dbg.target.TargetProcess;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;

public class TestKnownArchDebuggerMappingOpinion implements DebuggerMappingOpinion {
	public static final String ARCH = "test-known-arch";

	@Override
	public Set<DebuggerMappingOffer> offersForEnv(TargetEnvironment env, TargetProcess process,
			boolean includeOverrides) {
		if (!ARCH.equals(env.getArchitecture())) {
			return Set.of();
		}
		return Set.of(new DefaultDebuggerMappingOffer(process, 100, "Offer for test-known-arch",
			new LanguageID(DebuggerModelServiceTest.LANGID_TOYBE64), new CompilerSpecID("default"),
			Set.of()));
	}
}
