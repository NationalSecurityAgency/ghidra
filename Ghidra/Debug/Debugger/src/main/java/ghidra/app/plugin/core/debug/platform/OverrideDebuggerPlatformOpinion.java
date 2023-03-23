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

import java.util.*;
import java.util.stream.Collectors;

import ghidra.app.plugin.core.debug.mapping.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject;

/**
 * An "opinion" which offers every known compiler, but with only default mapping logic.
 */
public class OverrideDebuggerPlatformOpinion extends AbstractDebuggerPlatformOpinion {
	private static final LanguageCompilerSpecQuery ALL_SPECS =
		new LanguageCompilerSpecQuery(null, null, null, null, null);
	private static final Map<Endian, Set<DebuggerPlatformOffer>> CACHE = new HashMap<>();

	protected static class OverridePlatformOffer implements DebuggerPlatformOffer {

		private final String description;
		private final LanguageID languageID;
		private final CompilerSpecID cSpecID;
		private final int confidence;

		public OverridePlatformOffer(String description, LanguageID languageID,
				CompilerSpecID cSpecID, int confidence) {
			this.description = description;
			this.languageID = languageID;
			this.cSpecID = cSpecID;
			this.confidence = confidence;
		}

		@Override
		public String getDescription() {
			return description;
		}

		@Override
		public LanguageID getLanguageID() {
			return languageID;
		}

		@Override
		public CompilerSpecID getCompilerSpecID() {
			return cSpecID;
		}

		@Override
		public int getConfidence() {
			return confidence;
		}

		@Override
		public DebuggerPlatformMapper take(PluginTool tool, Trace trace) {
			return new OverrideDebuggerPlatformMapper(tool, trace, getCompilerSpec());
		}

		@Override
		public boolean isCreatorOf(DebuggerPlatformMapper mapper) {
			return mapper.getClass() == OverrideDebuggerPlatformMapper.class;
		}

		@Override
		public CompilerSpec getCompilerSpec() {
			return getCompilerSpec(languageID, cSpecID);
		}
	}

	protected static class OverrideDebuggerPlatformMapper extends DefaultDebuggerPlatformMapper {
		public OverrideDebuggerPlatformMapper(PluginTool tool, Trace trace, CompilerSpec cSpec) {
			super(tool, trace, cSpec);
		}
	}

	protected DebuggerPlatformOffer computeOfferForEndianAndLCSP(Endian endian,
			LanguageCompilerSpecPair lcsp) {
		try {
			LanguageDescription ldesc = lcsp.getLanguageDescription();
			return new OverridePlatformOffer("Override to " + lcsp,
				ldesc.getLanguageID(),
				lcsp.getCompilerSpecDescription().getCompilerSpecID(),
				ldesc.getEndian() == endian ? -10 : -20);
		}
		catch (LanguageNotFoundException | CompilerSpecNotFoundException e) {
			// It couldn't have been generated unless it existed
			throw new AssertionError(e);
		}
	}

	protected Set<DebuggerPlatformOffer> computeOffersForEndian(Endian endian) {
		LanguageService langServ = DefaultLanguageService.getLanguageService();
		return langServ.getLanguageCompilerSpecPairs(ALL_SPECS)
				.stream()
				.map(lcsp -> computeOfferForEndianAndLCSP(endian, lcsp))
				.collect(Collectors.toSet());
	}

	@Override
	protected Set<DebuggerPlatformOffer> getOffers(TraceObject object, long snap, TraceObject env,
			String debugger, String arch, String os, Endian endian, boolean includeOverrides) {
		if (!includeOverrides) {
			return Set.of();
		}
		synchronized (CACHE) {
			return CACHE.computeIfAbsent(endian, this::computeOffersForEndian);
		}
	}
}
