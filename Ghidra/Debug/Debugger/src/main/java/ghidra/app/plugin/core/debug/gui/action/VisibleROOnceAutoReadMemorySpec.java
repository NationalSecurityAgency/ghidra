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
package ghidra.app.plugin.core.debug.gui.action;

import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;

import javax.swing.Icon;

import com.google.common.collect.Range;

import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.AutoReadMemoryAction;
import ghidra.app.services.TraceRecorder;
import ghidra.async.AsyncUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.memory.*;
import ghidra.util.task.TaskMonitor;

public class VisibleROOnceAutoReadMemorySpec implements AutoReadMemorySpec {
	public static final String CONFIG_NAME = "READ_VIS_RO_ONCE";

	@Override
	public String getConfigName() {
		return CONFIG_NAME;
	}

	@Override
	public String getMenuName() {
		return AutoReadMemoryAction.NAME_VIS_RO_ONCE;
	}

	@Override
	public Icon getMenuIcon() {
		return AutoReadMemoryAction.ICON_VIS_RO_ONCE;
	}

	@Override
	public CompletableFuture<?> readMemory(PluginTool tool, DebuggerCoordinates coordinates,
			AddressSetView visible) {
		if (!coordinates.isAliveAndReadsPresent()) {
			return AsyncUtils.NIL;
		}
		TraceRecorder recorder = coordinates.getRecorder();
		AddressSet visibleAccessible =
			recorder.getAccessibleProcessMemory().intersect(visible);
		TraceMemoryManager mm = coordinates.getTrace().getMemoryManager();
		AddressSetView alreadyKnown =
			mm.getAddressesWithState(coordinates.getSnap(), visibleAccessible,
				s -> s == TraceMemoryState.KNOWN);
		AddressSet toRead = visibleAccessible.subtract(alreadyKnown);

		if (toRead.isEmpty()) {
			return AsyncUtils.NIL;
		}

		AddressSet everKnown = new AddressSet();
		for (AddressRange range : visible) {
			for (Entry<TraceAddressSnapRange, TraceMemoryState> ent : mm
					.getMostRecentStates(coordinates.getSnap(), range)) {
				everKnown.add(ent.getKey().getRange());
			}
		}
		AddressSet readOnly = new AddressSet();
		for (AddressRange range : visible) {
			for (TraceMemoryRegion region : mm
					.getRegionsIntersecting(Range.singleton(coordinates.getSnap()), range)) {
				if (region.isWrite()) {
					continue;
				}
				readOnly.add(region.getRange());
			}
		}
		toRead.delete(everKnown.intersect(readOnly));

		if (toRead.isEmpty()) {
			return AsyncUtils.NIL;
		}

		return recorder.captureProcessMemory(toRead, TaskMonitor.DUMMY, false);
	}
}
