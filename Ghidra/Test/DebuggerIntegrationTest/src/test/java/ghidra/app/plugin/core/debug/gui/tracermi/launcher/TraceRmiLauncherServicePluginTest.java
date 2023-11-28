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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assume.assumeTrue;

import java.util.*;

import org.junit.Before;
import org.junit.Test;

import db.Transaction;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerTest;
import ghidra.app.services.TraceRmiLauncherService;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer.*;
import ghidra.framework.OperatingSystem;
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
			public Map<String, ?> configureLauncher(TraceRmiLaunchOffer offer,
					Map<String, ?> arguments, RelPrompt relPrompt) {
				Map<String, Object> args = new HashMap<>(arguments);
				args.put("arg:1", file);
				args.put("env:OPT_START_CMD", "starti");
				return args;
			}
		};
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
			public Map<String, ?> configureLauncher(TraceRmiLaunchOffer offer,
					Map<String, ?> arguments, RelPrompt relPrompt) {
				Map<String, Object> args = new HashMap<>(arguments);
				args.put("env:OPT_TARGET_IMG", file);
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
