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
package ghidra.app.plugin.core.debug.service.model;

import static org.junit.Assert.assertEquals;

import java.util.Collection;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import generic.Unique;
import ghidra.app.plugin.core.debug.service.model.launch.DebuggerProgramLaunchOffer;
import ghidra.app.plugin.core.debug.service.model.launch.DebuggerProgramLaunchOpinion;
import ghidra.app.services.DebuggerModelService;
import ghidra.async.AsyncUtils;
import ghidra.dbg.DebuggerModelFactory;
import ghidra.dbg.model.TestDebuggerModelFactory;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class TestDebuggerProgramLaunchOpinion implements DebuggerProgramLaunchOpinion {

	static class TestDebuggerProgramLaunchOffer implements DebuggerProgramLaunchOffer {
		@Override
		public CompletableFuture<Void> launchProgram(TaskMonitor monitor, boolean prompt) {
			return AsyncUtils.NIL;
		}

		@Override
		public String getConfigName() {
			return "TEST";
		}

		@Override
		public String getMenuParentTitle() {
			return "Debug it";
		}

		@Override
		public String getMenuTitle() {
			return "in Fake Debugger";
		}
	}

	@Override
	public Collection<DebuggerProgramLaunchOffer> getOffers(Program program, PluginTool tool,
			DebuggerModelService service) {
		DebuggerModelFactory factory = Unique.assertOne(service.getModelFactories());
		assertEquals(TestDebuggerModelFactory.class, factory.getClass());

		return List.of(new TestDebuggerProgramLaunchOffer());
	}
}
