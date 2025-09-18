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
package agent.gdb.rmi;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertTrue;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;

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
import ghidra.framework.plugintool.AutoConfigState.PathIsFile;
import ghidra.pty.testutil.DummyProc;

public class GdbConnectorsTest extends AbstractRmiConnectorsTest {

	@Override
	protected List<ResourceFile> getPipLinkModules() {
		return List.of(
			Application.getModuleRootDir("Debugger-rmi-trace"),
			Application.getModuleRootDir("Debugger-agent-gdb"));
	}

	@Before
	public void setUpGdb() throws Exception {
		// Make sure system doesn't cause path failures to pass
		unpip("ghidragdb", "ghidratrace");
		// Ensure a compatible version of protobuf
		pip("protobuf==6.31.0");
	}

	@Test
	public void testLocalGdbSetup() throws Exception {
		pipOob("protobuf==3.19.0");
		try (LaunchResult result = doLaunch("gdb", Map.of("arg:1", chooseImage()))) {
			assertTrue(result.exception() instanceof EarlyTerminationException);
			assertThat(result.sessions().get("Shell").content(),
				Matchers.containsString("Would you like to install"));
		}
		try (LaunchResult result = doLaunch("gdb", Map.of("arg:1", chooseImage()))) {
			checkResult(result);
		}
	}

	@Test
	public void testLocalGdbWithImage() throws Exception {
		try (LaunchResult result = doLaunch("gdb", Map.of("arg:1", chooseImage()))) {
			checkResult(result);
		}
	}

	@Test
	public void testGdbQemuUser() throws Exception {
		PathIsFile image = createArmElfImage();
		program = AutoImporter.importByUsingBestGuess(image.path().toFile(), null, "/", this,
			new MessageLog(), monitor).getPrimaryDomainObject();
		programManager.openProgram(program);
		try (LaunchResult result = doLaunch("gdb + qemu", Map.ofEntries(
			Map.entry("arg:1", image),
			Map.entry("env:OPT_GDB_PATH", new PathIsFile(Path.of("gdb"))),
			Map.entry("env:GHIDRA_LANG_EXTTOOL_qemu_system", findQemu("qemu-arm")),
			Map.entry("env:OPT_PULL_ALL_SECTIONS", true)))) {
			checkResult(result);
		}
	}

	@Test
	public void testGdbQemuSys() throws Exception {
		autoMappingService
				.setAutoMapSpec(AutoMapSpec.fromConfigName(BySectionAutoMapSpec.CONFIG_NAME));
		PathIsFile dummy = createDummyQemuImage();
		createProgram();
		try (Transaction tx = program.openTransaction("Set name")) {
			program.setName(dummy.toString());
		}
		programManager.openProgram(program);
		try (LaunchResult result = doLaunch("gdb + qemu-system", Map.ofEntries(
			Map.entry("arg:1", dummy),
			Map.entry("env:OPT_GDB_PATH", new PathIsFile(Path.of("gdb"))),
			Map.entry("env:GHIDRA_LANG_EXTTOOL_qemu_system", findQemu("qemu-system-aarch64")),
			Map.entry("env:OPT_EXTRA_QEMU_ARGS", "-machine virt")))) {
			checkResult(result);
		}
	}

	@Test
	public void testGdbRemote() throws Exception {
		PathIsFile target = chooseImage();
		try (
				DummyProc gdbServer =
					DummyProc.run("gdbserver", ":9999", target.path().toAbsolutePath().toString());
				LaunchResult result = doLaunch("gdb remote", Map.ofEntries(
					Map.entry("arg:1", target),
					Map.entry("OPT_HOST", "localhost"),
					Map.entry("OPT_PORT", 9999)))) {
			checkResult(result);
		}
	}

	@Test
	public void testGdbViaSsh() throws Exception {
		pip("ghidragdb==%s".formatted(Application.getApplicationVersion()));
		try (LaunchResult result = doLaunch("gdb via ssh", Map.ofEntries(
			Map.entry("arg:1", "/bin/ls"),
			Map.entry("OPT_HOST", "localhost")))) {
			checkResult(result);
		}
	}

	@Test
	public void testGdbViaSshSetupGhidraGdb() throws Exception {
		try (LaunchResult result = doLaunch("gdb via ssh", Map.ofEntries(
			Map.entry("arg:1", "/bin/ls"),
			Map.entry("OPT_HOST", "localhost")))) {
			assertTrue(result.exception() instanceof EarlyTerminationException);
			assertThat(result.sessions().get("Shell").content(),
				Matchers.containsString("Would you like to install"));
		}
		try (LaunchResult result = doLaunch("gdb via ssh", Map.ofEntries(
			Map.entry("arg:1", "/bin/ls"),
			Map.entry("OPT_HOST", "localhost")))) {
			checkResult(result);
		}
	}

	@Test
	public void testGdbViaSshSetupProtobuf() throws Exception {
		pip("ghidragdb==%s".formatted(Application.getApplicationVersion()));
		// Overwrite with an incompatible version we don't include
		pipOob("protobuf==3.19.0");
		try (LaunchResult result = doLaunch("gdb via ssh", Map.ofEntries(
			Map.entry("arg:1", "/bin/ls"),
			Map.entry("OPT_HOST", "localhost")))) {
			assertTrue(result.exception() instanceof EarlyTerminationException);
			assertThat(result.sessions().get("Shell").content(),
				Matchers.containsString("Would you like to install"));
		}
		try (LaunchResult result = doLaunch("gdb via ssh", Map.ofEntries(
			Map.entry("arg:1", "/bin/ls"),
			Map.entry("OPT_HOST", "localhost")))) {
			checkResult(result);
		}
	}

	@Test
	public void testGdbServerViaSsh() throws Exception {
		PathIsFile target = chooseImage();
		createProgram();
		try (LaunchResult result = doLaunch("gdb + gdbserver via ssh", Map.ofEntries(
			Map.entry("arg:1", target.toString())))) {
			checkResult(result);
		}
	}
}
