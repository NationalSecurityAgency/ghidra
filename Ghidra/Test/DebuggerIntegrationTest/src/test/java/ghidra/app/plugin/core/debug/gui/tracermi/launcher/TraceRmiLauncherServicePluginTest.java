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

import static org.junit.Assert.*;
import static org.junit.Assume.*;

import java.nio.file.Paths;
import java.util.*;

import org.junit.Before;
import org.junit.Test;

import db.Transaction;
import generic.jar.ResourceFile;
import ghidra.app.plugin.core.analysis.AnalysisBackgroundCommand;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerTest;
import ghidra.app.services.TraceRmiLauncherService;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.LoadResults;
import ghidra.debug.api.ValStr;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer.*;
import ghidra.framework.Application;
import ghidra.framework.OperatingSystem;
import ghidra.framework.cmd.Command;
import ghidra.framework.plugintool.AutoConfigState.PathIsFile;
import ghidra.program.model.listing.Program;
import ghidra.util.task.ConsoleTaskMonitor;

public class TraceRmiLauncherServicePluginTest extends AbstractGhidraHeadedDebuggerTest {
	TraceRmiLauncherService launcherService;

	@Before
	public void setupRmiLauncherTest() throws Exception {
		launcherService = addPlugin(tool, TraceRmiLauncherServicePlugin.class);
	}

	protected TraceRmiLaunchOffer findByTitle(Collection<TraceRmiLaunchOffer> offers,
			String title) {
		return offers.stream().filter(o -> o.getTitle().equals(title)).findFirst().get();
	}

	@Test
	public void testGetOffers() throws Exception {
		createProgram(getSLEIGH_X86_64_LANGUAGE());

		assertFalse(launcherService.getOffers(program).isEmpty());
	}

	protected LaunchConfigurator gdbFileOnly(String file) {
		return new LaunchConfigurator() {
			@Override
			public Map<String, ValStr<?>> configureLauncher(TraceRmiLaunchOffer offer,
					Map<String, ValStr<?>> arguments, RelPrompt relPrompt) {
				Map<String, ValStr<?>> args = new HashMap<>(arguments);
				args.put("arg:1", new ValStr<>(new PathIsFile(Paths.get(file)), file));
				args.put("env:OPT_START_CMD", ValStr.str("starti"));
				return args;
			}
		};
	}

	@Test
	public void testGetClassName() throws Exception {
		ResourceFile rf = Application.getModuleDataFile("TestResources", "HelloWorld.class");
		try (LoadResults<Program> results = ProgramLoader.builder()
				.source(rf.getFile(false))
				.project(env.getProject())
				.monitor(monitor)
				.load()) {
			program = results.getPrimaryDomainObject(this);
		}
		AutoAnalysisManager analyzer = AutoAnalysisManager.getAnalysisManager(program);
		analyzer.reAnalyzeAll(null);
		Command<Program> cmd = new AnalysisBackgroundCommand(analyzer, false);
		tool.execute(cmd, program);
		waitForBusyTool(tool);
		assertEquals("HelloWorld", TraceRmiLauncherServicePlugin.tryProgramJvmClass(program));
	}

	// @Test // This is currently hanging the test machine. The gdb process is left running
	public void testLaunchLocalGdb() throws Exception {
		assumeTrue(OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.LINUX);

		createProgram(getSLEIGH_X86_64_LANGUAGE());
		try (Transaction tx = program.openTransaction("Rename")) {
			program.setName("bash");
		}
		programManager.openProgram(program);

		TraceRmiLaunchOffer offer = findByTitle(launcherService.getOffers(program), "gdb");

		try (LaunchResult result =
			offer.launchProgram(new ConsoleTaskMonitor(), gdbFileOnly("/usr/bin/bash"))) {
			if (result.exception() != null) {
				throw new AssertionError(result.exception());
			}

			assertEquals("bash", result.trace().getName());
			assertEquals(getSLEIGH_X86_64_LANGUAGE(), result.trace().getBaseLanguage());
		}
	}

	protected LaunchConfigurator dbgengFileOnly(String file) {
		return new LaunchConfigurator() {
			@Override
			public Map<String, ValStr<?>> configureLauncher(TraceRmiLaunchOffer offer,
					Map<String, ValStr<?>> arguments, RelPrompt relPrompt) {
				Map<String, ValStr<?>> args = new HashMap<>(arguments);
				args.put("env:OPT_TARGET_IMG", new ValStr<>(new PathIsFile(Paths.get(file)), file));
				return args;
			}
		};
	}

	@Test
	public void testLaunchLocalDbgeng() throws Exception {
		assumeTrue(OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS);

		createProgram(getSLEIGH_X86_64_LANGUAGE());
		try (Transaction tx = program.openTransaction("Rename")) {
			program.setName("notepad.exe");
		}
		programManager.openProgram(program);

		TraceRmiLaunchOffer offer = findByTitle(launcherService.getOffers(program), "dbgeng");

		try (LaunchResult result =
			offer.launchProgram(new ConsoleTaskMonitor(), dbgengFileOnly("notepad.exe"))) {
			if (result.exception() != null) {
				throw new AssertionError(result.exception());
			}

			assertEquals("notepad.exe", result.trace().getName());
			assertEquals(getSLEIGH_X86_64_LANGUAGE(), result.trace().getBaseLanguage());
		}
	}
}
