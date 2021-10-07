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
package ghidra.app.plugin.core.debug.platform.gdb;

import java.util.*;
import java.util.stream.Collectors;

import org.apache.commons.lang3.tuple.Pair;

import ghidra.app.plugin.core.debug.mapping.*;
import ghidra.dbg.target.*;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;

public class DefaultGdbDebuggerMappingOpinion implements DebuggerMappingOpinion {
	public static final String EXTERNAL_TOOL = "gnu";
	public static final CompilerSpecID PREFERRED_CSPEC_ID = new CompilerSpecID("gcc");

	private static final Map<Pair<String, Endian>, List<LanguageCompilerSpecPair>> CACHE =
		new HashMap<>();

	/**
	 * An opinion-specific offer class so that offers can be recognized in unit testing
	 */
	protected static class GdbDefaultOffer extends DefaultDebuggerMappingOffer {
		public GdbDefaultOffer(TargetObject target, int confidence, String description,
				LanguageCompilerSpecPair lcsp, Collection<String> extraRegNames) {
			super(target, confidence, description, lcsp.languageID, lcsp.compilerSpecID,
				extraRegNames);
		}
	}

	public static List<LanguageCompilerSpecPair> getCompilerSpecsForGnu(String arch,
			Endian endian) {
		synchronized (CACHE) {
			return CACHE.computeIfAbsent(Pair.of(arch, endian), p -> {
				LanguageService langServ = DefaultLanguageService.getLanguageService();
				return langServ.getLanguageCompilerSpecPairs(
					new ExternalLanguageCompilerSpecQuery(arch, EXTERNAL_TOOL,
						endian, null, PREFERRED_CSPEC_ID));
			});
		}
	}

	public static boolean isGdb(TargetEnvironment env) {
		if (env == null) {
			return false;
		}
		if (!env.getDebugger().toLowerCase().contains("gdb")) {
			return false;
		}
		return true;
	}

	public static boolean isLinux(TargetEnvironment env) {
		if (env == null) {
			return false;
		}
		if (!env.getOperatingSystem().contains("Linux")) {
			return false;
		}
		return true;
	}

	protected Set<DebuggerMappingOffer> offersForLanguageAndCSpec(TargetObject target, String arch,
			Endian endian, LanguageCompilerSpecPair lcsp) {
		return Set.of(new GdbDefaultOffer(target, 10, "Default GDB for " + arch, lcsp, Set.of()));
	}

	@Override
	public Set<DebuggerMappingOffer> offersForEnv(TargetEnvironment env, TargetProcess process,
			boolean includeOverrides) {
		if (!isGdb(env)) {
			return Set.of();
		}
		Endian endian = DebuggerMappingOpinion.getEndian(env);
		String arch = env.getArchitecture();

		return getCompilerSpecsForGnu(arch, endian).stream()
				.flatMap(lcsp -> offersForLanguageAndCSpec(process, arch, endian, lcsp).stream())
				.collect(Collectors.toSet());
	}
}
