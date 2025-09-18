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
package agent;

import static org.junit.Assert.assertEquals;
import static org.junit.Assume.assumeFalse;
import static org.junit.Assume.assumeTrue;

import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import org.junit.Before;

import generic.Unique;
import generic.jar.ResourceFile;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerIntegrationTest;
import ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesPlugin;
import ghidra.app.plugin.core.debug.gui.tracermi.launcher.AbstractTraceRmiLaunchOffer.NoStaticMappingException;
import ghidra.app.plugin.core.debug.gui.tracermi.launcher.TraceRmiLauncherServicePlugin;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingServicePlugin;
import ghidra.app.services.DebuggerAutoMappingService;
import ghidra.app.services.TraceRmiLauncherService;
import ghidra.debug.api.ValStr;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer.*;
import ghidra.framework.Application;
import ghidra.framework.OperatingSystem;
import ghidra.framework.plugintool.AutoConfigState.PathIsFile;
import ghidra.util.SystemUtilities;

public abstract class AbstractRmiConnectorsTest
		extends AbstractGhidraHeadedDebuggerIntegrationTest {
	protected TraceRmiLauncherService launchService;
	protected DebuggerAutoMappingService autoMappingService;

	protected String getPythonCmd() {
		return "python";
	}

	protected abstract List<ResourceFile> getPipLinkModules();

	protected void unpip(String... specs) throws Exception {
		List<String> args = new ArrayList<>();
		args.addAll(List.of(getPythonCmd(), "-m", "pip", "uninstall", "-y"));
		args.addAll(List.of(specs));
		int result = new ProcessBuilder().command(args).inheritIO().start().waitFor();
		assertEquals("pip failed", 0, result);
	}

	protected void pipOob(String... specs) throws Exception {
		List<String> args = new ArrayList<>();
		args.addAll(List.of(getPythonCmd(), "-m", "pip", "install"));
		args.addAll(List.of(specs));
		int result = new ProcessBuilder().command(args).inheritIO().start().waitFor();
		assertEquals("pip failed", 0, result);
	}

	protected void pip(String... specs) throws Exception {
		List<String> args = new ArrayList<>();
		args.addAll(List.of(getPythonCmd(), "-m", "pip", "install", "--no-index"));
		for (ResourceFile root : Application.getApplicationRootDirectories()) {
			if (root.getAbsolutePath().contains("ghidra.bin")) {
				for (; root != null; root = root.getParentFile()) {
					if (root.getName().equals("ghidra.bin")) {
						args.addAll(List.of("-f", root.getAbsolutePath() + "/ExternalPyWheels"));
					}
				}
			}
		}
		for (ResourceFile module : getPipLinkModules()) {
			args.addAll(List.of("-f", module.getAbsolutePath() + "/build/pypkg/dist"));
		}
		args.addAll(List.of(specs));
		int result = new ProcessBuilder().command(args).inheritIO().start().waitFor();
		assertEquals("pip failed", 0, result);
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
				return title.contains("ssh") &&
					OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS
							? PromptMode.ALWAYS
							: PromptMode.NEVER;
			}
		});
	}

	protected void checkResult(LaunchResult result) {
		if (result.exception() != null &&
			!(result.exception() instanceof NoStaticMappingException)) {
			throw new AssertionError(result);
		}
	}

	@Before
	public void setUpRmiConnectorsTest() throws Exception {
		// Check manual
		assumeFalse(SystemUtilities.isInTestingBatchMode());

		addPlugin(tool, DebuggerStaticMappingServicePlugin.class);
		addPlugin(tool, DebuggerModulesPlugin.class);
		autoMappingService =
			Objects.requireNonNull(tool.getService(DebuggerAutoMappingService.class));
		launchService = addPlugin(tool, TraceRmiLauncherServicePlugin.class);
	}

}
