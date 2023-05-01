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
package ghidra.app.plugin.core.debug.platform.dbgeng;

import java.util.Collection;
import java.util.List;

import ghidra.app.plugin.core.debug.service.model.launch.*;
import ghidra.dbg.DebuggerModelFactory;
import ghidra.dbg.util.PathUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

public class DbgDebuggerProgramLaunchOpinion extends AbstractDebuggerProgramLaunchOpinion {
	protected static final List<Class<? extends DebuggerProgramLaunchOffer>> OFFER_CLASSES =
		List.of(
			InVmDbgengDebuggerProgramLaunchOffer.class,
			GadpDbgengDebuggerProgramLaunchOffer.class,
			InVmDbgmodelDebuggerProgramLaunchOffer.class,
			GadpDbgmodelDebuggerProgramLaunchOffer.class);

	protected static abstract class AbstractDbgDebuggerProgramLaunchOffer
			extends AbstractDebuggerProgramLaunchOffer {

		public AbstractDbgDebuggerProgramLaunchOffer(Program program, PluginTool tool,
				DebuggerModelFactory factory) {
			super(program, tool, factory);
		}

		@Override
		protected List<String> getLauncherPath() {
			return PathUtils.parse("");
		}
	}

	@FactoryClass("agent.dbgeng.DbgEngInJvmDebuggerModelFactory")
	protected static class InVmDbgengDebuggerProgramLaunchOffer
			extends AbstractDbgDebuggerProgramLaunchOffer {

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

	@FactoryClass("agent.dbgeng.gadp.DbgEngGadpDebuggerModelFactory")
	protected static class GadpDbgengDebuggerProgramLaunchOffer
			extends AbstractDbgDebuggerProgramLaunchOffer {

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

	@FactoryClass("agent.dbgmodel.DbgModelInJvmDebuggerModelFactory")
	protected static class InVmDbgmodelDebuggerProgramLaunchOffer
			extends AbstractDbgDebuggerProgramLaunchOffer {

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

	@FactoryClass("agent.dbgmodel.gadp.DbgModelGadpDebuggerModelFactory")
	protected static class GadpDbgmodelDebuggerProgramLaunchOffer
			extends AbstractDbgDebuggerProgramLaunchOffer {

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
	protected Collection<Class<? extends DebuggerProgramLaunchOffer>> getOfferClasses() {
		return OFFER_CLASSES;
	}
}
