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

import ghidra.app.plugin.core.debug.service.model.launch.*;
import ghidra.app.services.DebuggerModelService;
import ghidra.dbg.DebuggerModelFactory;
import ghidra.dbg.target.TargetLauncher.TargetCmdLineLauncher;
import ghidra.dbg.target.TargetMethod.ParameterDescription;
import ghidra.dbg.util.ConfigurableFactory.Property;
import ghidra.dbg.util.PathUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

public class GdbDebuggerProgramLaunchOpinion implements DebuggerProgramLaunchOpinion {
	protected static abstract class AbstractGdbDebuggerProgramLaunchOffer
			extends AbstractDebuggerProgramLaunchOffer {

		public AbstractGdbDebuggerProgramLaunchOffer(Program program, PluginTool tool,
				DebuggerModelFactory factory) {
			super(program, tool, factory);
		}

		@Override
		public String getMenuParentTitle() {
			return "Debug " + program.getName();
		}

		@Override
		protected List<String> getLauncherPath() {
			return PathUtils.parse("Inferiors[1]");
		}

		@Override
		protected Map<String, ?> generateDefaultLauncherArgs(
				Map<String, ParameterDescription<?>> params) {
			return Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, program.getExecutablePath());
		}
	}

	protected class InVmGdbDebuggerProgramLaunchOffer
			extends AbstractGdbDebuggerProgramLaunchOffer {
		private static final String FACTORY_CLS_NAME = "agent.gdb.GdbInJvmDebuggerModelFactory";

		public InVmGdbDebuggerProgramLaunchOffer(Program program, PluginTool tool,
				DebuggerModelFactory factory) {
			super(program, tool, factory);
		}

		@Override
		public String getConfigName() {
			return "IN-VM GDB";
		}

		@Override
		public String getMenuTitle() {
			return "in GDB locally IN-VM";
		}
	}

	protected class GadpGdbDebuggerProgramLaunchOffer
			extends AbstractGdbDebuggerProgramLaunchOffer {
		private static final String FACTORY_CLS_NAME =
			"agent.gdb.gadp.GdbLocalDebuggerModelFactory";

		public GadpGdbDebuggerProgramLaunchOffer(Program program, PluginTool tool,
				DebuggerModelFactory factory) {
			super(program, tool, factory);
		}

		@Override
		public String getConfigName() {
			return "GADP GDB";
		}

		@Override
		public String getMenuTitle() {
			return "in GDB locally via GADP";
		}
	}

	protected class SshGdbDebuggerProgramLaunchOffer extends AbstractGdbDebuggerProgramLaunchOffer {
		private static final String FACTORY_CLS_NAME = "agent.gdb.GdbOverSshDebuggerModelFactory";

		public SshGdbDebuggerProgramLaunchOffer(Program program, PluginTool tool,
				DebuggerModelFactory factory) {
			super(program, tool, factory);
		}

		@Override
		public String getConfigName() {
			return "SSH GDB";
		}

		@Override
		public String getQuickTitle() {
			Map<String, Property<?>> opts = factory.getOptions();
			return String.format("in GDB via ssh:%s@%s",
				opts.get("SSH username").getValue(),
				opts.get("SSH hostname").getValue());
		}

		@Override
		public String getMenuTitle() {
			return "in GDB via ssh";
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
			if (clsName.equals(InVmGdbDebuggerProgramLaunchOffer.FACTORY_CLS_NAME)) {
				offers.add(new InVmGdbDebuggerProgramLaunchOffer(program, tool, factory));
			}
			else if (clsName.equals(GadpGdbDebuggerProgramLaunchOffer.FACTORY_CLS_NAME)) {
				offers.add(new GadpGdbDebuggerProgramLaunchOffer(program, tool, factory));
			}
			else if (clsName.equals(SshGdbDebuggerProgramLaunchOffer.FACTORY_CLS_NAME)) {
				offers.add(new SshGdbDebuggerProgramLaunchOffer(program, tool, factory));
			}
		}
		return offers;
	}
}
