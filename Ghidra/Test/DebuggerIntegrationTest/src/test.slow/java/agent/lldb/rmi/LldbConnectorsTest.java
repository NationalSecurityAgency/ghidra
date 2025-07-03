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
package agent.lldb.rmi;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeFalse;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import org.hamcrest.Matchers;
import org.junit.*;

import agent.AbstractRmiConnectorsTest;
import db.Transaction;
import generic.jar.ResourceFile;
import ghidra.app.plugin.core.debug.gui.action.BySectionAutoMapSpec;
import ghidra.app.plugin.core.debug.gui.tracermi.launcher.AbstractTraceRmiLaunchOffer.EarlyTerminationException;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.debug.api.action.AutoMapSpec;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer.LaunchResult;
import ghidra.framework.Application;
import ghidra.framework.OperatingSystem;
import ghidra.framework.plugintool.AutoConfigState.PathIsFile;
import ghidra.pty.testutil.DummyProc;

/**
 * NOTE: On Windows, these tests may need to be run with lldb's version of Python at the front of
 * PATH, and its lib and DLLs dirs at the front of PYTHONPATH. It's probably easiest to just get
 * lldb working in a command prompt. Ensure that it can import socket, and then re-launch Eclipse
 * from there.
 */
public class LldbConnectorsTest extends AbstractRmiConnectorsTest {

	@Override
	protected List<ResourceFile> getPipLinkModules() {
		return List.of(
			Application.getModuleRootDir("Debugger-rmi-trace"),
			Application.getModuleRootDir("Debugger-agent-lldb"));
	}

	@Before
	public void setupLldb() throws Exception {
		// Make sure system doesn't cause path failures to pass
		unpip("ghidralldb", "ghidratrace");
		// Ensure a compatible version of protobuf
		pip("protobuf==6.31.0");
	}

	/**
	 * This also doesn't quite work correctly on Windows. The prompt appears, but the user is not
	 * allowed to answer the question before the next lldb script command is run, which finds the
	 * package missing and exits with code 253. May just have to cut losses there. The message hits
	 * the screen, and this circumstance <em>should</em> be rare.
	 * 
	 * @throws Exception because
	 */
	@Test
	public void testLocalLldbSetup() throws Exception {
		pipOob("protobuf==3.19.0");
		try (LaunchResult result = doLaunch("lldb", Map.of("arg:1", chooseImage()))) {
			assertTrue(result.exception() instanceof EarlyTerminationException);
			assertThat(result.sessions().get("Shell").content(),
				Matchers.containsString("Would you like to install"));
		}
		// NOTE: lldb will not let me prompt the user, so cannot test automatic mitigation
	}

	@Test
	public void testLocalLldbWithImage() throws Exception {
		try (LaunchResult result = doLaunch("lldb", Map.ofEntries(
			Map.entry("arg:1", chooseImage()),
			Map.entry("env:OPT_START_CMD", "process launch --stop-at-entry")))) {
			checkResult(result);
		}
	}

	@Test
	@Ignore("TODO")
	public void testLldbQemuUser() throws Exception {
		assumeFalse(OperatingSystem.WINDOWS == OperatingSystem.CURRENT_OPERATING_SYSTEM);
		PathIsFile image = createArmElfImage();
		program = AutoImporter.importByUsingBestGuess(image.path().toFile(), null, "/", this,
			new MessageLog(), monitor).getPrimaryDomainObject();
		programManager.openProgram(program);
		try (LaunchResult result = doLaunch("lldb + qemu", Map.ofEntries(
			Map.entry("arg:1", image),
			Map.entry("env:OPT_LLDB_PATH", new PathIsFile(Path.of("lldb"))),
			Map.entry("env:GHIDRA_LANG_EXTTOOL_qemu_system", findQemu("qemu-arm")),
			Map.entry("env:OPT_PULL_ALL_SECTIONS", true)))) {
			checkResult(result);
		}
	}

	@Test
	@Ignore("TODO")
	public void testLldbQemuSys() throws Exception {
		autoMappingService
				.setAutoMapSpec(AutoMapSpec.fromConfigName(BySectionAutoMapSpec.CONFIG_NAME));
		PathIsFile dummy = createDummyQemuImage();
		createProgram();
		try (Transaction tx = program.openTransaction("Set name")) {
			program.setName(dummy.toString());
		}
		programManager.openProgram(program);
		try (LaunchResult result = doLaunch("lldb + qemu-system", Map.ofEntries(
			Map.entry("arg:1", dummy),
			Map.entry("env:OPT_LLDB_PATH", new PathIsFile(Path.of("lldb"))),
			Map.entry("env:GHIDRA_LANG_EXTTOOL_qemu_system", findQemu("qemu-system-aarch64")),
			Map.entry("env:OPT_EXTRA_QEMU_ARGS", "-machine virt")))) {
			checkResult(result);
		}
	}

	/**
	 * This has proven difficult to test on Windows, probably because the version of lldb and
	 * gdbserver I'm using are not compatible?
	 * 
	 * @throws Exception because
	 */
	@Test
	public void testLldbRemoteGdb() throws Exception {
		PathIsFile target = chooseImage();
		try (
				DummyProc gdbServer =
					DummyProc.run("gdbserver", ":9999", target.path().toAbsolutePath().toString());
				LaunchResult result = doLaunch("lldb remote (gdb)", Map.ofEntries(
					Map.entry("arg:1", target),
					Map.entry("OPT_HOST", "localhost"),
					Map.entry("OPT_PORT", 9999)))) {
			checkResult(result);
		}
	}

	@Test
	public void testLldbViaSsh() throws Exception {
		pip("ghidralldb==%s".formatted(Application.getApplicationVersion()));
		try (LaunchResult result = doLaunch("lldb via ssh", Map.ofEntries(
			Map.entry("arg:1", "/bin/ls"),
			Map.entry("OPT_HOST", "localhost")))) {
			checkResult(result);
		}
	}

	@Test
	public void testLldbViaSshSetupGhidraLldb() throws Exception {
		try (LaunchResult result = doLaunch("lldb via ssh", Map.ofEntries(
			Map.entry("arg:1", "/bin/ls"),
			Map.entry("OPT_HOST", "localhost")))) {
			assertTrue(result.exception() instanceof EarlyTerminationException);
			assertThat(result.sessions().get("Shell").content(),
				Matchers.containsString("Would you like to install"));
		}
		try (LaunchResult result = doLaunch("lldb via ssh", Map.ofEntries(
			Map.entry("arg:1", "/bin/ls"),
			Map.entry("OPT_HOST", "localhost")))) {
			checkResult(result);
		}
	}

	@Test
	public void testLldbViaSshSetupProtobuf() throws Exception {
		pip("ghidralldb==%s".formatted(Application.getApplicationVersion()));
		// Overwrite with an incompatible version we don't include
		pipOob("protobuf==3.19.0");
		try (LaunchResult result = doLaunch("lldb via ssh", Map.ofEntries(
			Map.entry("arg:1", "/bin/ls"),
			Map.entry("OPT_HOST", "localhost")))) {
			assertTrue(result.exception() instanceof EarlyTerminationException);
			assertThat(result.sessions().get("Shell").content(),
				Matchers.containsString("Would you like to install"));
		}
		try (LaunchResult result = doLaunch("lldb via ssh", Map.ofEntries(
			Map.entry("arg:1", "/bin/ls"),
			Map.entry("OPT_HOST", "localhost")))) {
			checkResult(result);
		}
	}
}
