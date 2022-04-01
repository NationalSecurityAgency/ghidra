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
package ghidra.app.plugin.core.debug.platform.frida;

import java.util.*;

import ghidra.app.plugin.core.debug.service.model.launch.*;
import ghidra.app.services.DebuggerModelService;
import ghidra.dbg.DebuggerModelFactory;
import ghidra.dbg.util.PathUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

public class FridaDebuggerProgramLaunchOpinion implements DebuggerProgramLaunchOpinion {
	protected static abstract class AbstractFridaDebuggerProgramLaunchOffer
			extends AbstractDebuggerProgramLaunchOffer {

		public AbstractFridaDebuggerProgramLaunchOffer(Program program, PluginTool tool,
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

	}

	protected class InVmFridaDebuggerProgramLaunchOffer
			extends AbstractFridaDebuggerProgramLaunchOffer {
		private static final String FACTORY_CLS_NAME = "agent.frida.FridaInJvmDebuggerModelFactory";

		public InVmFridaDebuggerProgramLaunchOffer(Program program, PluginTool tool,
				DebuggerModelFactory factory) {
			super(program, tool, factory);
		}

		@Override
		public String getConfigName() {
			return "IN-VM Frida";
		}

		@Override
		public String getMenuTitle() {
			return "in Frida locally IN-VM";
		}
	}

	protected class GadpFridaDebuggerProgramLaunchOffer
			extends AbstractFridaDebuggerProgramLaunchOffer {
		private static final String FACTORY_CLS_NAME =
			"agent.frida.gadp.FridaLocalDebuggerModelFactory";

		public GadpFridaDebuggerProgramLaunchOffer(Program program, PluginTool tool,
				DebuggerModelFactory factory) {
			super(program, tool, factory);
		}

		@Override
		public String getConfigName() {
			return "GADP Frida";
		}

		@Override
		public String getMenuTitle() {
			return "in Frida locally via GADP";
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
			if (clsName.equals(InVmFridaDebuggerProgramLaunchOffer.FACTORY_CLS_NAME)) {
				offers.add(new InVmFridaDebuggerProgramLaunchOffer(program, tool, factory));
			}
			else if (clsName.equals(GadpFridaDebuggerProgramLaunchOffer.FACTORY_CLS_NAME)) {
				offers.add(new GadpFridaDebuggerProgramLaunchOffer(program, tool, factory));
			}
		}
		return offers;
	}
}
