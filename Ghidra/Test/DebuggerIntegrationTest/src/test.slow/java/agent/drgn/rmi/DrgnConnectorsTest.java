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
package agent.drgn.rmi;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.FileNotFoundException;
import java.util.List;
import java.util.Map;

import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;

import agent.AbstractRmiConnectorsTest;
import generic.jar.ResourceFile;
import ghidra.app.plugin.core.debug.gui.tracermi.launcher.AbstractTraceRmiLaunchOffer.EarlyTerminationException;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer.LaunchResult;
import ghidra.framework.Application;
import ghidra.framework.plugintool.AutoConfigState.PathIsFile;

public class DrgnConnectorsTest extends AbstractRmiConnectorsTest {

	@Override
	protected List<ResourceFile> getPipLinkModules() {
		return List.of(
			Application.getModuleRootDir("Debugger-rmi-trace"),
			Application.getModuleRootDir("Debugger-agent-drgn"));
	}

	protected PathIsFile chooseCore() throws FileNotFoundException {
		return new PathIsFile(Application
				.getModuleDataFile("TestResources", AbstractDrgnTraceRmiTest.CORE)
				.getFile(true)
				.toPath());
	}

	@Before
	public void setUpDrgn() throws Exception {
		// Make sure system doesn't cause path failures to pass
		unpip("ghidradrgn", "ghidratrace");
		// Ensure a compatible version of protobuf
		pip("protobuf==6.31.0");
	}

	@Test
	public void testLocalDrgnSetup() throws Exception {
		pipOob("protobuf==3.19.0");
		try (LaunchResult result = doLaunch("drgn core", Map.ofEntries(
			Map.entry("env:OPT_TARGET_IMG", chooseCore())))) {
			assertTrue(result.exception() instanceof EarlyTerminationException);
			assertThat(result.sessions().get("Shell").content(),
				Matchers.containsString("Would you like to install"));
		}
		try (LaunchResult result = doLaunch("drgn core", Map.ofEntries(
			Map.entry("env:OPT_TARGET_IMG", chooseCore())))) {
			checkResult(result);
		}
	}

	@Test
	public void testLocalDrgnWithCore() throws Exception {
		try (LaunchResult result = doLaunch("drgn core", Map.ofEntries(
			Map.entry("env:OPT_TARGET_IMG", chooseCore())))) {
			checkResult(result);
		}
	}
}
