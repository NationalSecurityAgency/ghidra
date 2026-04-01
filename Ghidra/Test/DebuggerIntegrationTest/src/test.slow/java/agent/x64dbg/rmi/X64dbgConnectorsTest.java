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
package agent.x64dbg.rmi;

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

public class X64dbgConnectorsTest extends AbstractRmiConnectorsTest {

	@Override
	protected String getPythonCmd() {
		return "C:\\Python313\\python";
	}

	@Override
	protected List<ResourceFile> getPipLinkModules() {
		return List.of(
			Application.getModuleRootDir("Debugger-rmi-trace"),
			Application.getModuleRootDir("Debugger-agent-x64dbg"));
	}

	@Before
	public void setUpX64Dbg() throws Exception {
		// Make sure system doesn't cause path failures to pass
		unpip("ghidraxdbg", "ghidratrace");
		// Ensure a compatible version of protobuf
		pip("protobuf>=6.31.0");
	}

	@Test
	public void testLocalX64dbgWithImage() throws Exception {
		try (LaunchResult result = doLaunch("x64dbg", Map.ofEntries(
			Map.entry("env:OPT_TARGET_IMG", chooseImage()),
			Map.entry("env:OPT_X64DBG_EXE", new PathIsFile(Path.of("x64dbg.exe"))),
			Map.entry("env:OPT_PYTHON_EXE",
				new PathIsFile(Path.of(getPythonCmd())))))) {
			checkResult(result);
		}
	}

	@Test
	public void testLocalX64dbgWithImageBat() throws Exception {
		try (LaunchResult result = doLaunch("x64dbg (.bat)", Map.ofEntries(
			Map.entry("env:OPT_TARGET_IMG", chooseImage()),
			Map.entry("env:OPT_PYTHON_EXE",
				new PathIsFile(Path.of(getPythonCmd())))))) {
			checkResult(result);
		}
	}

	@Test
	public void testLocalX64dbgSetup() throws Exception {
		pipOob("protobuf==3.19.0");
		try (LaunchResult result = doLaunch("x64dbg", Map.ofEntries(
			Map.entry("env:OPT_TARGET_IMG", chooseImage()),
			Map.entry("env:OPT_X64DBG_EXE", new PathIsFile(Path.of("x64dbg.exe"))),
			Map.entry("env:OPT_PYTHON_EXE",
				new PathIsFile(Path.of(getPythonCmd())))))) {
			assertThat(result.exception(), instanceOf(EarlyTerminationException.class));
			assertThat(result.sessions().get("Shell").content(),
				containsString("Would you like to install"));
		}
		try (LaunchResult result = doLaunch("x64dbg", Map.ofEntries(
			Map.entry("env:OPT_TARGET_IMG", chooseImage()),
			Map.entry("env:OPT_X64DBG_EXE", new PathIsFile(Path.of("x64dbg.exe"))),
			Map.entry("env:OPT_PYTHON_EXE",
				new PathIsFile(Path.of(getPythonCmd())))))) {
			checkResult(result);
		}
	}

	@Test
	public void testLocalX64dbgSetupBat() throws Exception {
		pipOob("protobuf==3.19.0");
		try (LaunchResult result = doLaunch("x64dbg (.bat)", Map.ofEntries(
			Map.entry("env:OPT_TARGET_IMG", chooseImage()),
			Map.entry("env:OPT_PYTHON_EXE",
				new PathIsFile(Path.of(getPythonCmd())))))) {
			assertThat(result.exception(), instanceOf(EarlyTerminationException.class));
			assertThat(result.sessions().get("Shell").content(),
				containsString("Would you like to install"));
		}
		try (LaunchResult result = doLaunch("x64dbg (.bat)", Map.ofEntries(
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
	public void testX64dbgViaSsh() throws Exception {
		pip("ghidratrace==%s".formatted(Application.getApplicationVersion()));
		pip("ghidraxdbg==%s".formatted(Application.getApplicationVersion()));
		try (LaunchResult result = doLaunch("x64dbg via ssh", Map.ofEntries(
			Map.entry("env:OPT_TARGET_IMG", chooseImage()),
			Map.entry("env:OPT_X64DBG_EXE", new PathIsFile(Path.of("x64dbg.exe"))),
			Map.entry("OPT_HOST", "localhost")))) {
			checkResult(result);
		}
	}

	@Test
	public void testX64dbgViaSshSetupProtobuf() throws Exception {
		// NB: If you fail on the next line, delete everything (ghidradbg,
		//   ghidratrace, google, protobuf) from site-packages
		pip("ghidraxdbg==%s".formatted(Application.getApplicationVersion()));
		// Overwrite with an incompatible version we don't include
		pipOob("protobuf==3.19.0");
		try (LaunchResult result = doLaunch("x64dbg via ssh", Map.ofEntries(
			Map.entry("env:OPT_TARGET_IMG", chooseImage()),
			Map.entry("env:OPT_X64DBG_EXE", new PathIsFile(Path.of("x64dbg.exe"))),
			Map.entry("OPT_HOST", "localhost")))) {
			assertTrue(result.exception() instanceof EarlyTerminationException);
			assertThat(result.sessions().get("Shell").content(),
				Matchers.containsString("Would you like to install"));
		}
		try (LaunchResult result = doLaunch("x64dbg via ssh", Map.ofEntries(
			Map.entry("env:OPT_TARGET_IMG", chooseImage()),
			Map.entry("env:OPT_X64DBG_EXE", new PathIsFile(Path.of("x64dbg.exe"))),
			Map.entry("OPT_HOST", "localhost")))) {
			checkResult(result);
		}
	}

	@Test
	public void testX64dbgViaSshSetupGhidraDbg() throws Exception {
		try (LaunchResult result = doLaunch("x64dbg via ssh", Map.ofEntries(
			Map.entry("env:OPT_TARGET_IMG", chooseImage()),
			Map.entry("env:OPT_X64DBG_EXE", new PathIsFile(Path.of("x64dbg.exe"))),
			Map.entry("OPT_HOST", "localhost")))) {
			assertTrue(result.exception() instanceof EarlyTerminationException);
			assertThat(result.sessions().get("Shell").content(),
				Matchers.containsString("Would you like to install"));
		}
		try (LaunchResult result = doLaunch("x64dbg via ssh", Map.ofEntries(
			Map.entry("env:OPT_TARGET_IMG", chooseImage()),
			Map.entry("env:OPT_X64DBG_EXE", new PathIsFile(Path.of("x64dbg.exe"))),
			Map.entry("OPT_HOST", "localhost")))) {
			checkResult(result);
		}
	}

}
