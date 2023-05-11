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
package ghidra.app.plugin.core.debug.platform.lldb;

import java.util.Collection;
import java.util.List;

import ghidra.app.plugin.core.debug.service.model.launch.*;
import ghidra.dbg.DebuggerModelFactory;
import ghidra.dbg.util.PathUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

public class LldbDebuggerProgramLaunchOpinion extends AbstractDebuggerProgramLaunchOpinion {
	protected static final List<Class<? extends DebuggerProgramLaunchOffer>> OFFER_CLASSES =
		List.of(
			InVmLldbDebuggerProgramLaunchOffer.class,
			GadpLldbDebuggerProgramLaunchOffer.class);

	protected static abstract class AbstractLldbDebuggerProgramLaunchOffer
			extends AbstractDebuggerProgramLaunchOffer {

		public AbstractLldbDebuggerProgramLaunchOffer(Program program, PluginTool tool,
				DebuggerModelFactory factory) {
			super(program, tool, factory);
		}

		@Override
		protected List<String> getLauncherPath() {
			return PathUtils.parse("");
		}

	}

	@FactoryClass("agent.lldb.LldbInJvmDebuggerModelFactory")
	protected static class InVmLldbDebuggerProgramLaunchOffer
			extends AbstractLldbDebuggerProgramLaunchOffer {

		public InVmLldbDebuggerProgramLaunchOffer(Program program, PluginTool tool,
				DebuggerModelFactory factory) {
			super(program, tool, factory);
		}

		@Override
		public String getConfigName() {
			return "IN-VM LLDB";
		}

		@Override
		public String getMenuTitle() {
			return "in LLDB locally IN-VM";
		}
	}

	@FactoryClass("agent.lldb.gadp.LldbGadpDebuggerModelFactory")
	protected static class GadpLldbDebuggerProgramLaunchOffer
			extends AbstractLldbDebuggerProgramLaunchOffer {

		public GadpLldbDebuggerProgramLaunchOffer(Program program, PluginTool tool,
				DebuggerModelFactory factory) {
			super(program, tool, factory);
		}

		@Override
		public String getConfigName() {
			return "GADP LLDB";
		}

		@Override
		public String getMenuTitle() {
			return "in LLDB locally via GADP";
		}
	}

	@Override
	protected Collection<Class<? extends DebuggerProgramLaunchOffer>> getOfferClasses() {
		return OFFER_CLASSES;
	}
}
