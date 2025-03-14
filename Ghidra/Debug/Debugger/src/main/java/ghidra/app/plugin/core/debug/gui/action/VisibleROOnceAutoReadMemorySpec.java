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

import ghidra.app.plugin.core.debug.gui.DebuggerResources.AutoReadMemoryAction;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.memory.*;

public class VisibleROOnceAutoReadMemorySpec implements AutoReadMemorySpec {
	public static final String CONFIG_NAME = "1_READ_VIS_RO_ONCE";

	@Override
	public boolean equals(Object obj) {
		return this.getClass() == obj.getClass();
	}

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
	public CompletableFuture<Boolean> readMemory(PluginTool tool, DebuggerCoordinates coordinates,
			AddressSetView visible) {
		if (!coordinates.isAliveAndReadsPresent()) {
			return CompletableFuture.completedFuture(false);
		}
		Target target = coordinates.getTarget();
		TraceMemoryManager mm = coordinates.getTrace().getMemoryManager();
		long snap = coordinates.getSnap();
		AddressSetView alreadyKnown = mm.getAddressesWithState(snap, visible,
			s -> s == TraceMemoryState.KNOWN || s == TraceMemoryState.ERROR);
		AddressSet toRead = visible.subtract(alreadyKnown);

		if (toRead.isEmpty()) {
			return CompletableFuture.completedFuture(false);
		}

		AddressSet everKnown = new AddressSet();
		for (AddressRange range : visible) {
			for (Entry<TraceAddressSnapRange, TraceMemoryState> ent : mm.getMostRecentStates(snap,
				range)) {
				everKnown.add(ent.getKey().getRange());
			}
		}
		AddressSet readOnly = new AddressSet();
		for (AddressRange range : visible) {
			for (TraceMemoryRegion region : mm.getRegionsIntersecting(Lifespan.at(snap), range)) {
				if (region.isWrite(snap)) {
					continue;
				}
				readOnly.add(region.getRange(snap));
			}
		}
		toRead.delete(everKnown.intersect(readOnly));

		if (toRead.isEmpty()) {
			return CompletableFuture.completedFuture(false);
		}

		return doRead(tool, monitor -> target.readMemoryAsync(toRead, monitor));
	}
}
