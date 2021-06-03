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
import ghidra.dbg.util.PathUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

public class DbgDebuggerProgramLaunchOpinion implements DebuggerProgramLaunchOpinion {
	protected static abstract class AbstractDbgDebuggerProgramLaunchOffer
			extends AbstractDebuggerProgramLaunchOffer {

		public AbstractDbgDebuggerProgramLaunchOffer(Program program, PluginTool tool,
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

	protected class InVmDbgengDebuggerProgramLaunchOffer
			extends AbstractDbgDebuggerProgramLaunchOffer {
		private static final String FACTORY_CLS_NAME =
			"agent.dbgeng.DbgEngInJvmDebuggerModelFactory";

		public InVmDbgengDebuggerProgramLaunchOffer(Program program, PluginTool tool,
				DebuggerModelFactory factory) {
			super(program, tool, factory);
		}

		@Override
		public String getConfigName() {
			return "IN-VM dbgeng";
		}

		@Override
		public String getMenuTitle() {
			return "in dbgeng locally IN-VM";
		}
	}

	protected class GadpDbgengDebuggerProgramLaunchOffer
			extends AbstractDbgDebuggerProgramLaunchOffer {
		private static final String FACTORY_CLS_NAME =
			"agent.dbgeng.gadp.DbgEngLocalDebuggerModelFactory";

		public GadpDbgengDebuggerProgramLaunchOffer(Program program, PluginTool tool,
				DebuggerModelFactory factory) {
			super(program, tool, factory);
		}

		@Override
		public String getConfigName() {
			return "GADP dbgeng";
		}

		@Override
		public String getMenuTitle() {
			return "in dbgeng locally via GADP";
		}
	}

	protected class InVmDbgmodelDebuggerProgramLaunchOffer
			extends AbstractDbgDebuggerProgramLaunchOffer {
		private static final String FACTORY_CLS_NAME =
			"agent.dbgmodel.DbgModelInJvmDebuggerModelFactory";

		public InVmDbgmodelDebuggerProgramLaunchOffer(Program program, PluginTool tool,
				DebuggerModelFactory factory) {
			super(program, tool, factory);
		}

		@Override
		public String getConfigName() {
			return "IN-VM dbgmodel";
		}

		@Override
		public String getMenuTitle() {
			return "in dbgmodel locally IN-VM";
		}
	}

	protected class GadpDbgmodelDebuggerProgramLaunchOffer
			extends AbstractDbgDebuggerProgramLaunchOffer {
		private static final String FACTORY_CLS_NAME =
			"agent.dbgmodel.gadp.DbgModelLocalDebuggerModelFactory";

		public GadpDbgmodelDebuggerProgramLaunchOffer(Program program, PluginTool tool,
				DebuggerModelFactory factory) {
			super(program, tool, factory);
		}

		@Override
		public String getConfigName() {
			return "GADP dbgmodel";
		}

		@Override
		public String getMenuTitle() {
			return "in dbgmodel locally via GADP";
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
			if (clsName.equals(InVmDbgengDebuggerProgramLaunchOffer.FACTORY_CLS_NAME)) {
				offers.add(new InVmDbgengDebuggerProgramLaunchOffer(program, tool, factory));
			}
			else if (clsName.equals(GadpDbgengDebuggerProgramLaunchOffer.FACTORY_CLS_NAME)) {
				offers.add(new GadpDbgengDebuggerProgramLaunchOffer(program, tool, factory));
			}
			else if (clsName.equals(InVmDbgmodelDebuggerProgramLaunchOffer.FACTORY_CLS_NAME)) {
				offers.add(new InVmDbgmodelDebuggerProgramLaunchOffer(program, tool, factory));
			}
			else if (clsName.equals(GadpDbgmodelDebuggerProgramLaunchOffer.FACTORY_CLS_NAME)) {
				offers.add(new GadpDbgmodelDebuggerProgramLaunchOffer(program, tool, factory));
			}
		}
		return offers;
	}
}
