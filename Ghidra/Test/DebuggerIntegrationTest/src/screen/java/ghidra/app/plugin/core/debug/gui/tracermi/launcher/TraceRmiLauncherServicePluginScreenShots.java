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

import java.util.Map;

import org.junit.Test;

import ghidra.app.plugin.core.debug.gui.objects.components.DebuggerMethodInvocationDialog;
import ghidra.app.plugin.core.terminal.TerminalProvider;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer;
import ghidra.test.ToyProgramBuilder;
import help.screenshot.GhidraScreenShotGenerator;

public class TraceRmiLauncherServicePluginScreenShots extends GhidraScreenShotGenerator {
	TraceRmiLauncherServicePlugin servicePlugin;

	protected void captureLauncherByTitle(String title, Map<String, ?> args) throws Throwable {
		servicePlugin = addPlugin(tool, TraceRmiLauncherServicePlugin.class);

		ToyProgramBuilder pb = new ToyProgramBuilder("demo", false);

		TraceRmiLaunchOffer offer = servicePlugin.getOffers(pb.getProgram())
				.stream()
				.filter(o -> title.equals(o.getTitle()))
				.findAny()
				.orElseThrow();

		AbstractTraceRmiLaunchOffer aoff = (AbstractTraceRmiLaunchOffer) offer;
		aoff.saveLauncherArgs(args, aoff.getParameters());

		runSwingLater(() -> servicePlugin.configureAndLaunch(offer));

		captureDialog(DebuggerMethodInvocationDialog.class);
	}

	@Test
	public void testCaptureGdbLauncher() throws Throwable {
		captureLauncherByTitle("gdb", Map.of("arg:1", "/home/user/demo"));
	}

	@Test
	public void testCaptureGdbTerminal() throws Throwable {
		servicePlugin = addPlugin(tool, TraceRmiLauncherServicePlugin.class);

		TraceRmiLaunchOffer offer = servicePlugin.getOffers(null)
				.stream()
				.filter(o -> "raw gdb".equals(o.getTitle()))
				.findAny()
				.orElseThrow();

		servicePlugin.relaunch(offer);

		captureIsolatedProvider(TerminalProvider.class, 600, 600);
	}
}
