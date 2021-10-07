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

import java.util.*;

import ghidra.app.plugin.core.debug.service.model.launch.*;
import ghidra.app.services.DebuggerModelService;
import ghidra.dbg.DebuggerModelFactory;
import ghidra.dbg.target.TargetLauncher.TargetCmdLineLauncher;
import ghidra.dbg.target.TargetMethod.ParameterDescription;
import ghidra.dbg.util.PathUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

public class LldbDebuggerProgramLaunchOpinion implements DebuggerProgramLaunchOpinion {
	protected static abstract class AbstractLldbDebuggerProgramLaunchOffer
			extends AbstractDebuggerProgramLaunchOffer {

		public AbstractLldbDebuggerProgramLaunchOffer(Program program, PluginTool tool,
				DebuggerModelFactory factory) {
			super(program, tool, factory);
		}

		@Override
		public String getMenuParentTitle() {
			return "Debug " + program.getName();
		}

		@Override
		protected List<String> getLauncherPath() {
			return PathUtils.parse("");
		}

		@Override
		protected Map<String, ?> generateDefaultLauncherArgs(
				Map<String, ParameterDescription<?>> params) {
			return Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, program.getExecutablePath());
		}
	}

	protected class InVmLldbDebuggerProgramLaunchOffer
			extends AbstractLldbDebuggerProgramLaunchOffer {
		private static final String FACTORY_CLS_NAME = "agent.lldb.LldbInJvmDebuggerModelFactory";

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

	protected class GadpLldbDebuggerProgramLaunchOffer
			extends AbstractLldbDebuggerProgramLaunchOffer {
		private static final String FACTORY_CLS_NAME =
			"agent.lldb.gadp.LldbLocalDebuggerModelFactory";

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
	public Collection<DebuggerProgramLaunchOffer> getOffers(Program program, PluginTool tool,
			DebuggerModelService service) {
		String exe = program.getExecutablePath();
		if (exe == null || "".equals(exe.trim())) {
			return List.of();
		}
		List<DebuggerProgramLaunchOffer> offers = new ArrayList<>();
		for (DebuggerModelFactory factory : service.getModelFactories()) {
			if (!factory.isCompatible()) {
				continue;
			}
			String clsName = factory.getClass().getName();
			if (clsName.equals(InVmLldbDebuggerProgramLaunchOffer.FACTORY_CLS_NAME)) {
				offers.add(new InVmLldbDebuggerProgramLaunchOffer(program, tool, factory));
			}
			else if (clsName.equals(GadpLldbDebuggerProgramLaunchOffer.FACTORY_CLS_NAME)) {
				offers.add(new GadpLldbDebuggerProgramLaunchOffer(program, tool, factory));
			}
		}
		return offers;
	}
}
