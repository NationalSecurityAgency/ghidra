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
package ghidra.app.plugin.core.debug.gui.memory;

import java.util.Set;

import org.junit.*;

import com.google.common.collect.Range;

import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.test.ToyProgramBuilder;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.util.database.UndoableTransaction;
import help.screenshot.GhidraScreenShotGenerator;

public class DebuggerRegionsPluginScreenShots extends GhidraScreenShotGenerator {

	DebuggerTraceManagerService traceManager;
	DebuggerRegionsPlugin regionsPlugin;
	ToyDBTraceBuilder tb;

	@Before
	public void setUpMine() throws Throwable {
		traceManager = addPlugin(tool, DebuggerTraceManagerServicePlugin.class);
		regionsPlugin = addPlugin(tool, DebuggerRegionsPlugin.class);

		tb = new ToyDBTraceBuilder("echo", ToyProgramBuilder._X64);
	}

	@After
	public void tearDownMine() {
		tb.close();
	}

	@Test
	public void testCaptureDebuggerRegionsPlugin() throws Throwable {
		try (UndoableTransaction tid = tb.startTransaction()) {
			long snap = tb.trace.getTimeManager().createSnapshot("First").getKey();

			tb.trace.getMemoryManager()
					.addRegion("[400000:40ffff]", Range.atLeast(snap),
						tb.range(0x00400000, 0x0040ffff),
						Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
			tb.trace.getMemoryManager()
					.addRegion("[600000:60ffff]", Range.atLeast(snap),
						tb.range(0x00600000, 0x0060ffff),
						Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.WRITE));
			tb.trace.getMemoryManager()
					.addRegion("[7fac0000:7facffff]", Range.atLeast(snap),
						tb.range(0x7fac0000, 0x7facffff),
						Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
			tb.trace.getMemoryManager()
					.addRegion("[7fae0000:7faeffff]", Range.atLeast(snap),
						tb.range(0x7fae0000, 0x7faeffff),
						Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.WRITE));

			traceManager.openTrace(tb.trace);
			traceManager.activateTrace(tb.trace);

			captureIsolatedProvider(DebuggerRegionsProvider.class, 900, 300);
		}
	}
}
