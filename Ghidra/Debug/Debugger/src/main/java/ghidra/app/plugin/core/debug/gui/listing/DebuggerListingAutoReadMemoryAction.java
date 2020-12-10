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
package ghidra.app.plugin.core.debug.gui.listing;

import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;

import com.google.common.collect.Range;

import docking.action.builder.MultiStateActionBuilder;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.AutoReadMemoryAction;
import ghidra.app.services.TraceRecorder;
import ghidra.async.AsyncUtils;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.AutoConfigState.ConfigFieldCodec;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.address.*;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.memory.*;
import ghidra.util.task.TaskMonitor;

public interface DebuggerListingAutoReadMemoryAction extends AutoReadMemoryAction {
	public interface AutoReadMemorySpec {
		AutoReadMemorySpec READ_NONE = new ReadNoneMemorySpec();
		AutoReadMemorySpec READ_VISIBLE = new ReadVisibleMemorySpec();
		AutoReadMemorySpec READ_VIS_RO_ONCE = new ReadVisibleROOnceMemorySpec();

		public static class AutoReadMemorySpecConfigFieldCodec
				implements ConfigFieldCodec<AutoReadMemorySpec> {
			@Override
			public AutoReadMemorySpec read(SaveState state, String name,
					AutoReadMemorySpec current) {
				String specName = state.getString(name, null);
				return fromConfigName(specName);
			}

			@Override
			public void write(SaveState state, String name, AutoReadMemorySpec value) {
				state.putString(name, value.getConfigName());
			}
		}

		static AutoReadMemorySpec fromConfigName(String spec) {
			switch (spec) {
				default:
				case "READ_VIS_RO_ONCE":
					return READ_VIS_RO_ONCE;
			}
		}

		String getConfigName();

		/**
		 * Perform the automatic read, if applicable
		 * 
		 * <p>
		 * Note, the implementation should perform all the error handling. The returned future is
		 * for follow-up purposes only, and should always complete normally.
		 * 
		 * @param coordinates the listing's current coordinates
		 * @param visible the listing's visible addresses
		 * @return a future that completes when the memory has been read
		 */
		CompletableFuture<Void> readMemory(DebuggerCoordinates coordinates, AddressSetView visible);
	}

	class ReadNoneMemorySpec implements AutoReadMemorySpec {
		static final String CONFIG_NAME = "READ_NONE";

		@Override
		public String getConfigName() {
			return CONFIG_NAME;
		}

		@Override
		public CompletableFuture<Void> readMemory(DebuggerCoordinates coordinates,
				AddressSetView visible) {
			return AsyncUtils.NIL;
		}
	}

	class ReadVisibleMemorySpec implements AutoReadMemorySpec {
		static final String CONFIG_NAME = "READ_VISIBLE";

		@Override
		public String getConfigName() {
			return CONFIG_NAME;
		}

		@Override
		public CompletableFuture<Void> readMemory(DebuggerCoordinates coordinates,
				AddressSetView visible) {
			if (!coordinates.isAliveAndPresent()) {
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

			return recorder.captureProcessMemory(toRead, TaskMonitor.DUMMY);
		}
	}

	class ReadVisibleROOnceMemorySpec implements AutoReadMemorySpec {
		static final String CONFIG_NAME = "READ_VIS_RO_ONCE";

		@Override
		public String getConfigName() {
			return CONFIG_NAME;
		}

		@Override
		public CompletableFuture<Void> readMemory(DebuggerCoordinates coordinates,
				AddressSetView visible) {
			if (!coordinates.isAliveAndPresent()) {
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

			return recorder.captureProcessMemory(toRead, TaskMonitor.DUMMY);
		}
	}

	static MultiStateActionBuilder<AutoReadMemorySpec> builder(Plugin owner) {
		MultiStateActionBuilder<AutoReadMemorySpec> builder = AutoReadMemoryAction.builder(owner);
		return builder
				.toolBarGroup(NAME)
				.performActionOnButtonClick(true)
				.addState(NAME_NONE, ICON_NONE, AutoReadMemorySpec.READ_NONE)
				.addState(NAME_VISIBLE, ICON_VISIBLE, AutoReadMemorySpec.READ_VISIBLE)
				.addState(NAME_VIS_RO_ONCE, ICON_VIS_RO_ONCE, AutoReadMemorySpec.READ_VIS_RO_ONCE);
	}
}
