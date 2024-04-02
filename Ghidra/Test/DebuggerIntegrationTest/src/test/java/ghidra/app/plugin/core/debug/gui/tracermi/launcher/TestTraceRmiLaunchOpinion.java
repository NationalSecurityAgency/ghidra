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
package ghidra.app.plugin.core.debug.gui.tracermi.launcher;

import static org.junit.Assert.assertEquals;

import java.net.SocketAddress;
import java.util.*;

import ghidra.dbg.target.TargetMethod.ParameterDescription;
import ghidra.debug.api.tracermi.TerminalSession;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer;
import ghidra.debug.spi.tracermi.TraceRmiLaunchOpinion;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class TestTraceRmiLaunchOpinion implements TraceRmiLaunchOpinion {

	public static class TestTraceRmiLaunchOffer extends AbstractTraceRmiLaunchOffer {
		private static final ParameterDescription<String> PARAM_DESC_IMAGE =
			ParameterDescription.create(String.class, "image", true, "",
				PARAM_DISPLAY_IMAGE, "Image to execute");

		public TestTraceRmiLaunchOffer(TraceRmiLauncherServicePlugin plugin, Program program) {
			super(plugin, program);
		}

		public Program getProgram() {
			return program;
		}

		@Override
		public String getConfigName() {
			return "TEST";
		}

		@Override
		public String getTitle() {
			return "Test";
		}

		@Override
		public String getDescription() {
			return "Test launch offer";
		}

		@Override
		public Map<String, ParameterDescription<?>> getParameters() {
			return Map.ofEntries(Map.entry(PARAM_DESC_IMAGE.name, PARAM_DESC_IMAGE));
		}

		@Override
		public boolean requiresImage() {
			return false;
		}

		@Override
		protected void launchBackEnd(TaskMonitor monitor, Map<String, TerminalSession> sessions,
				Map<String, ?> args, SocketAddress address) throws Exception {
		}

		@Override
		public LaunchResult launchProgram(TaskMonitor monitor, LaunchConfigurator configurator) {
			assertEquals(PromptMode.NEVER, configurator.getPromptMode());
			Map<String, ?> args =
				configurator.configureLauncher(this, loadLastLauncherArgs(false), RelPrompt.NONE);
			return new LaunchResult(program, null, null, null, null,
				new RuntimeException("Test launcher cannot launch " + args.get("image")));
		}

		public void saveLauncherArgs(Map<String, ?> args) {
			super.saveLauncherArgs(args, getParameters());
		}
	}

	@Override
	public Collection<TraceRmiLaunchOffer> getOffers(TraceRmiLauncherServicePlugin plugin,
			Program program) {
		return List.of(new TestTraceRmiLaunchOffer(plugin, program));
	}
}
