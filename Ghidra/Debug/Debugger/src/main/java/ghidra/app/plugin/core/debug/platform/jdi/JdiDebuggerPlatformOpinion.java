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
package ghidra.app.plugin.core.debug.platform.jdi;

import java.util.Set;

import ghidra.app.plugin.core.debug.mapping.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.lang.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject;

public class JdiDebuggerPlatformOpinion extends AbstractDebuggerPlatformOpinion {
	protected static final LanguageID LANG_ID_JAVA = new LanguageID("JVM:BE:32:default");
	protected static final LanguageID LANG_ID_DALVIK = new LanguageID("Dalvik:LE:32:default");
	protected static final CompilerSpecID COMP_ID_DEFAULT = new CompilerSpecID("default");

	protected static class JdiDebuggerPlatformMapper extends DefaultDebuggerPlatformMapper {
		// TODO: Delete this class?
		public JdiDebuggerPlatformMapper(PluginTool tool, Trace trace, CompilerSpec cSpec) {
			super(tool, trace, cSpec);
		}
	}

	enum Offers implements DebuggerPlatformOffer {
		JAVA_VM("Java Virtual Machine", LANG_ID_JAVA, COMP_ID_DEFAULT),
		DALVIK_VM("Dalvik Virtual Machine", LANG_ID_DALVIK, COMP_ID_DEFAULT);

		final String description;
		final LanguageID langID;
		final CompilerSpecID cSpecID;

		private Offers(String description, LanguageID langID, CompilerSpecID cSpecID) {
			this.description = description;
			this.langID = langID;
			this.cSpecID = cSpecID;
		}

		@Override
		public String getDescription() {
			return description;
		}

		@Override
		public int getConfidence() {
			return 100;
		}

		@Override
		public CompilerSpec getCompilerSpec() {
			return getCompilerSpec(langID, cSpecID);
		}

		@Override
		public DebuggerPlatformMapper take(PluginTool tool, Trace trace) {
			return new JdiDebuggerPlatformMapper(tool, trace, getCompilerSpec());
		}
	}

	@Override
	protected Set<DebuggerPlatformOffer> getOffers(TraceObject object, long snap, TraceObject env,
			String debugger, String arch, String os, Endian endian) {
		if (debugger == null || arch == null || !debugger.contains("Java Debug Interface")) {
			return Set.of();
		}
		boolean isJava = arch.contains("OpenJDK");
		boolean isDalvik = arch.contains("Dalvik");
		// NOTE: Not worried about versions
		if (isJava) {
			return Set.of(Offers.JAVA_VM);
		}
		if (isDalvik) {
			return Set.of(Offers.DALVIK_VM);
		}
		return Set.of();
	}
}
