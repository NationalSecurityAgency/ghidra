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

import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeFalse;
import static org.junit.Assume.assumeTrue;

import java.io.FileOutputStream;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import org.junit.*;

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

/**
 * NOTE: On Windows, these tests may need to be run with lldb's version of Python at the front of
 * PATH, and it's lib and DLLs dirs at the front of PYTHONPATH. It's probably easiest to just get
 * lldb working in a command prompt. Ensure that it can import socket, and then re-launch Eclipse
 * from there.
 */
public class LldbConnectorsTest extends AbstractGhidraHeadedDebuggerIntegrationTest {
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
		assumeTrue(OperatingSystem.LINUX == OperatingSystem.CURRENT_OPERATING_SYSTEM);
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

			@Override
			public PromptMode getPromptMode() {
				return title.contains("ssh") ? PromptMode.ALWAYS : PromptMode.NEVER;
			}
		});
	}

	protected void checkResult(LaunchResult result) {
		if (result.exception() != null &&
			!(result.exception() instanceof NoStaticMappingException)) {
			throw new AssertionError(result);
		}
	}

	/**
	 * This also doesn't quite work correctly on Windows. The prompt appears, but the user is not
	 * allowed to answer the question before the next lldb script command is run, which finds the
	 * package missing and exits with code 253. May just have to cut losses there. The message hits
	 * the screen, and this circumstance <em>should</em> be rare.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testLocalLldbSetup() throws Exception {
		new ProcessBuilder().command("python", "-m", "pip", "install", "protobuf==3.19.0")
				.inheritIO()
				.start()
				.waitFor();
		try (LaunchResult result = doLaunch("lldb", Map.of("arg:1", chooseImage()))) {
			assertTrue(result.exception() instanceof SocketTimeoutException);
			TerminalSession term = Unique.assertOne(result.sessions().values());
			while (!term.isTerminated()) {
				Thread.sleep(1000);
			}
		}
		try (LaunchResult result = doLaunch("lldb", Map.of("arg:1", chooseImage()))) {
			checkResult(result);
		}
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
	 * @throws Exception
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
		try (LaunchResult result = doLaunch("lldb via ssh", Map.ofEntries(
			Map.entry("arg:1", "/bin/ls"),
			Map.entry("OPT_HOST", "localhost")))) {
			checkResult(result);
		}
	}

	@Test
	public void testLldbViaSshSetupGhidraLldb() throws Exception {
		// This only applies if we leave localhost in the dialog
		new ProcessBuilder().command("python", "-m", "pip", "uninstall", "ghidralldb")
				.inheritIO()
				.start()
				.waitFor();
		try (LaunchResult result = doLaunch("lldb via ssh", Map.ofEntries(
			Map.entry("arg:1", "/bin/ls"),
			Map.entry("OPT_HOST", "localhost")))) {
			assertTrue(result.exception() instanceof SocketTimeoutException);
			TerminalSession term = Unique.assertOne(result.sessions().values());
			while (!term.isTerminated()) {
				Thread.sleep(1000);
			}
		}
		try (LaunchResult result = doLaunch("lldb via ssh", Map.ofEntries(
			Map.entry("arg:1", "/bin/ls"),
			Map.entry("OPT_HOST", "localhost")))) {
			checkResult(result);
		}
	}

	@Test
	public void testLldbViaSshSetupProtobuf() throws Exception {
		new ProcessBuilder().command("python", "-m", "pip", "install", "protobuf==3.19.0")
				.inheritIO()
				.start()
				.waitFor();
		try (LaunchResult result = doLaunch("lldb via ssh", Map.ofEntries(
			Map.entry("arg:1", "/bin/ls"),
			Map.entry("OPT_HOST", "localhost")))) {
			assertTrue(result.exception() instanceof SocketTimeoutException);
			TerminalSession term = Unique.assertOne(result.sessions().values());
			while (!term.isTerminated()) {
				Thread.sleep(1000);
			}
		}
		try (LaunchResult result = doLaunch("lldb via ssh", Map.ofEntries(
			Map.entry("arg:1", "/bin/ls"),
			Map.entry("OPT_HOST", "localhost")))) {
			checkResult(result);
		}
	}
}
