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
import ghidra.debug.api.platform.DebuggerPlatformMapper;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject;

public class GdbDebuggerPlatformOpinion extends AbstractDebuggerPlatformOpinion {
	public static final String EXTERNAL_TOOL = "gnu";
	public static final CompilerSpecID GCC_CSPEC_ID = new CompilerSpecID("gcc");
	public static final CompilerSpecID WINDOWS_CSPEC_ID = new CompilerSpecID("windows");

	private static final Map<Pair<String, Endian>, List<LanguageCompilerSpecPair>> CACHE =
		new HashMap<>();

	public static List<LanguageCompilerSpecPair> getCompilerSpecsForGnu(String arch, String os,
			Endian endian) {
		CompilerSpecID prefferedCspecId = computePreferredSpecId(os);
		synchronized (CACHE) {
			return CACHE.computeIfAbsent(Pair.of(arch, endian), p -> {
				LanguageService langServ = DefaultLanguageService.getLanguageService();
				return langServ.getLanguageCompilerSpecPairs(
					new ExternalLanguageCompilerSpecQuery(arch, EXTERNAL_TOOL,
						endian, null, prefferedCspecId));
			});
		}
	}

	protected static CompilerSpecID computePreferredSpecId(String os) {
		String lower = os.toLowerCase();
		if (lower.contains("windows")) {
			return WINDOWS_CSPEC_ID;
		}
		// Just assume Linux (really AMD64 System V ABI)
		return GCC_CSPEC_ID;
	}

	protected static class GdbDebuggerPlatformOffer extends AbstractDebuggerPlatformOffer {
		public static GdbDebuggerPlatformOffer fromArchLCSP(String arch,
				LanguageCompilerSpecPair lcsp)
				throws CompilerSpecNotFoundException, LanguageNotFoundException {
			return new GdbDebuggerPlatformOffer("Default GDB for " + arch, lcsp.getCompilerSpec());
		}

		public GdbDebuggerPlatformOffer(String description, CompilerSpec cSpec) {
			super(description, cSpec);
		}

		@Override
		public int getConfidence() {
			return 100;
		}

		@Override
		public DebuggerPlatformMapper take(PluginTool tool, Trace trace) {
			return new GdbDebuggerPlatformMapper(tool, trace, cSpec);
		}

		@Override
		public boolean isCreatorOf(DebuggerPlatformMapper mapper) {
			return mapper.getClass() == GdbDebuggerPlatformMapper.class;
		}
	}

	protected static class GdbDebuggerPlatformMapper extends DefaultDebuggerPlatformMapper {
		public GdbDebuggerPlatformMapper(PluginTool tool, Trace trace, CompilerSpec cSpec) {
			super(tool, trace, cSpec);
		}
		// TODO: eflags<->rflags for amd64 / x86-64
	}

	protected Set<GdbDebuggerPlatformOffer> offersForLanguageAndCSpec(String arch, Endian endian,
			LanguageCompilerSpecPair lcsp)
			throws CompilerSpecNotFoundException, LanguageNotFoundException {
		return Set.of(GdbDebuggerPlatformOffer.fromArchLCSP(arch, lcsp));
	}

	@Override
	protected Set<DebuggerPlatformOffer> getOffers(TraceObject object, long snap, TraceObject env,
			String debugger, String arch, String os, Endian endian, boolean includeOverrides) {
		if (debugger == null || !"gdb".equals(debugger.toLowerCase())) {
			return Set.of();
		}
		return getCompilerSpecsForGnu(arch, os, endian).stream().flatMap(lcsp -> {
			try {
				return offersForLanguageAndCSpec(arch, endian, lcsp).stream();
			}
			catch (CompilerSpecNotFoundException | LanguageNotFoundException e) {
				throw new AssertionError(e);
			}
		}).collect(Collectors.toSet());
	}
}
