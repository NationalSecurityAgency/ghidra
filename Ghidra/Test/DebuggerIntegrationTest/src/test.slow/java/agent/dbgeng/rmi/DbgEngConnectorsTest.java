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
package agent.dbgeng.rmi;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.nio.file.Path;
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

public class DbgEngConnectorsTest extends AbstractRmiConnectorsTest {

	@Override
	protected String getPythonCmd() {
		return "C:\\Python313\\python";
	}

	@Override
	protected List<ResourceFile> getPipLinkModules() {
		return List.of(
			Application.getModuleRootDir("Debugger-rmi-trace"),
			Application.getModuleRootDir("Debugger-agent-dbgeng"));
	}

	@Before
	public void setUpDbgEng() throws Exception {
		// Make sure system doesn't cause path failures to pass
		unpip("ghidradbg", "ghidratrace");
		// Ensure a compatible version of protobuf
		pip("protobuf>=6.31.0");
	}

	@Test
	public void testLocalDbgWithImage() throws Exception {
		try (LaunchResult result = doLaunch("dbgeng", Map.ofEntries(
			Map.entry("env:OPT_TARGET_IMG", chooseImage()),
			Map.entry("env:OPT_PYTHON_EXE",
				new PathIsFile(Path.of(getPythonCmd())))))) {
			checkResult(result);
		}
	}

	@Test
	public void testLocalDbgWithImageBat() throws Exception {
		try (LaunchResult result = doLaunch("dbgeng (.bat)", Map.ofEntries(
			Map.entry("env:OPT_TARGET_IMG", chooseImage()),
			Map.entry("env:OPT_PYTHON_EXE",
				new PathIsFile(Path.of(getPythonCmd())))))) {
			checkResult(result);
		}
	}

	@Test
	public void testLocalDbgSetup() throws Exception {
		pipOob("protobuf==3.19.0");
		try (LaunchResult result = doLaunch("dbgeng", Map.ofEntries(
			Map.entry("env:OPT_TARGET_IMG", chooseImage()),
			Map.entry("env:OPT_PYTHON_EXE",
				new PathIsFile(Path.of(getPythonCmd())))))) {
			assertThat(result.exception(), instanceOf(EarlyTerminationException.class));
			assertThat(result.sessions().get("Shell").content(),
				containsString("Would you like to install"));
		}
		try (LaunchResult result = doLaunch("dbgeng", Map.ofEntries(
			Map.entry("env:OPT_TARGET_IMG", chooseImage()),
			Map.entry("env:OPT_PYTHON_EXE",
				new PathIsFile(Path.of(getPythonCmd())))))) {
			checkResult(result);
		}
	}

	@Test
	public void testLocalDbgSetupBat() throws Exception {
		pipOob("protobuf==3.19.0");
		try (LaunchResult result = doLaunch("dbgeng (.bat)", Map.ofEntries(
			Map.entry("env:OPT_TARGET_IMG", chooseImage()),
			Map.entry("env:OPT_PYTHON_EXE",
				new PathIsFile(Path.of(getPythonCmd())))))) {
			assertThat(result.exception(), instanceOf(EarlyTerminationException.class));
			assertThat(result.sessions().get("Shell").content(),
				containsString("Would you like to install"));
		}
		try (LaunchResult result = doLaunch("dbgeng (.bat)", Map.ofEntries(
			Map.entry("env:OPT_TARGET_IMG", chooseImage()),
			Map.entry("env:OPT_PYTHON_EXE",
				new PathIsFile(Path.of(getPythonCmd())))))) {
			checkResult(result);
		}
	}

	// NB: The next three tests tend to leave residual python processes running
	//  which will cause permissions problems when subsequent tests attempt
	//  to access python's site-packages

	@Test
	public void testDbgViaSsh() throws Exception {
		pip("ghidradbg==%s".formatted(Application.getApplicationVersion()));
		try (LaunchResult result = doLaunch("dbgeng via ssh", Map.ofEntries(
			Map.entry("env:OPT_TARGET_IMG", chooseImage()),
			Map.entry("OPT_HOST", "localhost")))) {
			checkResult(result);
		}
	}

	@Test
	public void testDbgViaSshSetupProtobuf() throws Exception {
		// NB: If you fail on the next line, delete everything (ghidradbg,
		//   ghidratrace, google, protobuf) from site-packages
		pip("ghidradbg==%s".formatted(Application.getApplicationVersion()));
		// Overwrite with an incompatible version we don't include
		pipOob("protobuf==3.19.0");
		try (LaunchResult result = doLaunch("dbgeng via ssh", Map.ofEntries(
			Map.entry("env:OPT_TARGET_IMG", chooseImage()),
			Map.entry("OPT_HOST", "localhost")))) {
			assertTrue(result.exception() instanceof EarlyTerminationException);
			assertThat(result.sessions().get("Shell").content(),
				Matchers.containsString("Would you like to install"));
		}
		try (LaunchResult result = doLaunch("dbgeng via ssh", Map.ofEntries(
			Map.entry("env:OPT_TARGET_IMG", chooseImage()),
			Map.entry("OPT_HOST", "localhost")))) {
			checkResult(result);
		}
	}

	@Test
	public void testDbgViaSshSetupGhidraDbg() throws Exception {
		try (LaunchResult result = doLaunch("dbgeng via ssh", Map.ofEntries(
			Map.entry("env:OPT_TARGET_IMG", chooseImage()),
			Map.entry("OPT_HOST", "localhost")))) {
			assertTrue(result.exception() instanceof EarlyTerminationException);
			assertThat(result.sessions().get("Shell").content(),
				Matchers.containsString("Would you like to install"));
		}
		try (LaunchResult result = doLaunch("dbgeng via ssh", Map.ofEntries(
			Map.entry("env:OPT_TARGET_IMG", chooseImage()),
			Map.entry("OPT_HOST", "localhost")))) {
			checkResult(result);
		}
	}

	// LATER?: kernel
	// LATER?: attach (usermode by PID)
	// LATER?: ext
	// LATER?: trace (TTD)
	// LATER?: remote (Start WinDbg and join session)
	// LATER?: svrcx (what scenario?)
}
