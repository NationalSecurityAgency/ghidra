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

import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeFalse;

import java.io.FileOutputStream;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import org.junit.Before;
import org.junit.Test;

import db.Transaction;
import generic.Unique;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerIntegrationTest;
import ghidra.app.plugin.core.debug.gui.action.BySectionAutoMapSpec;
import ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesPlugin;
import ghidra.app.plugin.core.debug.gui.tracermi.launcher.AbstractTraceRmiLaunchOffer.NoStaticMappingException;
import ghidra.app.plugin.core.debug.gui.tracermi.launcher.TraceRmiLauncherServicePlugin;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingServicePlugin;
import ghidra.app.services.DebuggerAutoMappingService;
import ghidra.app.services.TraceRmiLauncherService;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.debug.api.ValStr;
import ghidra.debug.api.action.AutoMapSpec;
import ghidra.debug.api.tracermi.TerminalSession;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer.*;
import ghidra.framework.OperatingSystem;
import ghidra.framework.plugintool.AutoConfigState.PathIsFile;
import ghidra.pty.testutil.DummyProc;
import ghidra.util.SystemUtilities;

public class GdbConnectorsTest extends AbstractGhidraHeadedDebuggerIntegrationTest {
	private TraceRmiLauncherService launchService;
	private DebuggerAutoMappingService autoMappingService;

	@Before
	public void checkManual() throws Exception {
		assumeFalse(SystemUtilities.isInTestingBatchMode());
		addPlugin(tool, DebuggerStaticMappingServicePlugin.class);
		addPlugin(tool, DebuggerModulesPlugin.class);
		autoMappingService =
			Objects.requireNonNull(tool.getService(DebuggerAutoMappingService.class));
		launchService = addPlugin(tool, TraceRmiLauncherServicePlugin.class);
	}

	protected PathIsFile chooseImage() {
		if (OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS) {
			return new PathIsFile(Path.of("C:\\Windows\\notepad.exe"));
		}
		return new PathIsFile(Path.of("/bin/ls"));
	}

	protected PathIsFile findQemu(String bin) {
		if (OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS) {
			return new PathIsFile(Path.of("C:\\msys64\\ucrt64\bin\\").resolve(bin));
		}
		return new PathIsFile(Path.of(bin));
	}

	protected PathIsFile createArmElfImage() throws Exception {
		Path tempSrc = Files.createTempFile("hw", ".c");
		Path tempObj = Files.createTempFile("hw", ".o");
		Path tempImg = Files.createTempFile("hw", "");
		try (OutputStream os = new FileOutputStream(tempSrc.toFile())) {
			os.write("""
					int main() {
						return 0;
					}
					""".getBytes());
		}
		new ProcessBuilder().command(
			"arm-linux-eabi-gcc", "-c",
			"-o", tempObj.toAbsolutePath().toString(),
			tempSrc.toAbsolutePath().toString()).inheritIO().start().waitFor();
		new ProcessBuilder().command(
			"arm-linux-eabi-ld",
			"-o", tempImg.toAbsolutePath().toString(),
			tempObj.toAbsolutePath().toString()).inheritIO().start().waitFor();
		return new PathIsFile(tempImg);
	}

	protected PathIsFile createDummyQemuImage() throws Exception {
		Path temp = Files.createTempFile("qemudummy", ".bin");
		try (OutputStream os = new FileOutputStream(temp.toFile())) {
			os.write(new byte[4096]);
		}
		return new PathIsFile(temp);
	}

	protected LaunchResult doLaunch(String title, Map<String, Object> args) {
		TraceRmiLaunchOffer offer = Unique.assertOne(
			launchService.getOffers(program).stream().filter(o -> o.getTitle().equals(title)));
		return offer.launchProgram(monitor, new LaunchConfigurator() {
			@Override
			public Map<String, ValStr<?>> configureLauncher(TraceRmiLaunchOffer offer,
					Map<String, ValStr<?>> arguments, RelPrompt relPrompt) {
				Map<String, ValStr<?>> newArgs = new HashMap<>(arguments);
				for (Map.Entry<String, Object> ent : args.entrySet()) {
					newArgs.put(ent.getKey(), ValStr.from(ent.getValue()));
				}
				return newArgs;
			}
		});
	}

	protected void checkResult(LaunchResult result) {
		if (result.exception() != null &&
			!(result.exception() instanceof NoStaticMappingException)) {
			throw new AssertionError(result);
		}
	}

	@Test
	public void testLocalGdbSetup() throws Exception {
		new ProcessBuilder().command("pip", "install", "protobuf==3.19.0")
				.inheritIO()
				.start()
				.waitFor();
		try (LaunchResult result = doLaunch("gdb", Map.of("arg:1", chooseImage()))) {
			assertTrue(result.exception() instanceof SocketTimeoutException);
			TerminalSession term = Unique.assertOne(result.sessions().values());
			while (!term.isTerminated()) {
				Thread.sleep(1000);
			}
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
		try (LaunchResult result = doLaunch("gdb via ssh", Map.ofEntries(
			Map.entry("arg:1", "/bin/ls"),
			Map.entry("OPT_HOST", "localhost")))) {
			checkResult(result);
		}
	}

	@Test
	public void testGdbViaSshSetupGhidraGdb() throws Exception {
		new ProcessBuilder().command("pip", "uninstall", "ghidragdb").inheritIO().start().waitFor();
		try (LaunchResult result = doLaunch("gdb via ssh", Map.ofEntries(
			Map.entry("arg:1", "/bin/ls"),
			Map.entry("OPT_HOST", "localhost")))) {
			assertTrue(result.exception() instanceof SocketTimeoutException);
			TerminalSession term = Unique.assertOne(result.sessions().values());
			while (!term.isTerminated()) {
				Thread.sleep(1000);
			}
		}
		try (LaunchResult result = doLaunch("gdb via ssh", Map.ofEntries(
			Map.entry("arg:1", "/bin/ls"),
			Map.entry("OPT_HOST", "localhost")))) {
			checkResult(result);
		}
	}

	@Test
	public void testGdbViaSshSetupProtobuf() throws Exception {
		new ProcessBuilder().command("pip", "install", "protobuf==3.19.0")
				.inheritIO()
				.start()
				.waitFor();
		try (LaunchResult result = doLaunch("gdb via ssh", Map.ofEntries(
			Map.entry("arg:1", "/bin/ls"),
			Map.entry("OPT_HOST", "localhost")))) {
			assertTrue(result.exception() instanceof SocketTimeoutException);
			TerminalSession term = Unique.assertOne(result.sessions().values());
			while (!term.isTerminated()) {
				Thread.sleep(1000);
			}
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
