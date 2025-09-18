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

import java.nio.ByteBuffer;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;

import javax.swing.Icon;

import db.Transaction;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.AutoReadMemoryAction;
import ghidra.app.plugin.core.debug.gui.control.TargetActionTask;
import ghidra.app.plugin.core.debug.service.emulation.ProgramEmulationUtils;
import ghidra.app.plugin.core.debug.utils.AbstractMappedMemoryBytesVisitor;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.debug.api.action.AutoReadMemorySpec;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.trace.model.*;
import ghidra.trace.model.memory.*;
import ghidra.util.task.TaskMonitor;

public enum BasicAutoReadMemorySpec implements AutoReadMemorySpec {
	/**
	 * Never automatically read memory
	 */
	NONE("0_READ_NONE", AutoReadMemoryAction.NAME_NONE, AutoReadMemoryAction.ICON_NONE) {
		@Override
		public CompletableFuture<Boolean> readMemory(PluginTool tool,
				DebuggerCoordinates coordinates, AddressSetView visible) {
			return CompletableFuture.completedFuture(false);
		}
	},
	/**
	 * Automatically read all visible memory
	 */
	VISIBLE("1_READ_VISIBLE", AutoReadMemoryAction.NAME_VISIBLE, AutoReadMemoryAction.ICON_VISIBLE) {
		@Override
		public CompletableFuture<Boolean> readMemory(PluginTool tool,
				DebuggerCoordinates coordinates,
				AddressSetView visible) {
			if (!coordinates.isAliveAndReadsPresent()) {
				return CompletableFuture.completedFuture(false);
			}
			Target target = coordinates.getTarget();
			TraceMemoryManager mm = coordinates.getTrace().getMemoryManager();
			AddressSetView alreadyKnown = mm.getAddressesWithState(coordinates.getSnap(), visible,
				s -> s == TraceMemoryState.KNOWN || s == TraceMemoryState.ERROR);
			AddressSet toRead = visible.subtract(alreadyKnown);

			if (toRead.isEmpty()) {
				return CompletableFuture.completedFuture(false);
			}

			return doRead(tool, monitor -> target.readMemoryAsync(toRead, monitor));
		}
	},
	/**
	 * Automatically read all visible memory, unless it is read-only, in which case, only read it if
	 * it has not already been read.
	 */
	VIS_RO_ONCE("2_READ_VIS_RO_ONCE", AutoReadMemoryAction.NAME_VIS_RO_ONCE, AutoReadMemoryAction.ICON_VIS_RO_ONCE) {
		@Override
		public CompletableFuture<Boolean> readMemory(PluginTool tool,
				DebuggerCoordinates coordinates,
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
				for (Entry<TraceAddressSnapRange, TraceMemoryState> ent : mm.getMostRecentStates(
					snap,
					range)) {
					everKnown.add(ent.getKey().getRange());
				}
			}
			AddressSet readOnly = new AddressSet();
			for (AddressRange range : visible) {
				for (TraceMemoryRegion region : mm.getRegionsIntersecting(Lifespan.at(snap),
					range)) {
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
	},
	/**
	 * Load memory from programs for "pure" emulation traces.
	 */
	LOAD_EMULATOR(null, null, null) {
		protected AddressSetView quantize(int blockBits, AddressSetView set) {
			if (blockBits == 1) {
				return set;
			}
			long blockMask = -1L << blockBits;
			AddressSet result = new AddressSet();
			// Not terribly efficient, but this is one range most of the time
			for (AddressRange range : set) {
				AddressSpace space = range.getAddressSpace();
				Address min = space.getAddress(range.getMinAddress().getOffset() & blockMask);
				Address max = space.getAddress(range.getMaxAddress().getOffset() | ~blockMask);
				result.add(new AddressRangeImpl(min, max));
			}
			return result;
		}

		@Override
		public CompletableFuture<Boolean> readMemory(PluginTool tool,
				DebuggerCoordinates coordinates, AddressSetView visible) {
			DebuggerStaticMappingService mappingService =
				tool.getService(DebuggerStaticMappingService.class);
			if (mappingService == null) {
				return CompletableFuture.completedFuture(false);
			}
			Trace trace = coordinates.getTrace();
			if (trace == null || coordinates.isAlive() ||
				!ProgramEmulationUtils.isEmulatedProgram(trace)) {
				// Never interfere with a live target
				return CompletableFuture.completedFuture(false);
			}
			TraceMemoryManager mm = trace.getMemoryManager();
			AddressSet toRead = new AddressSet(quantize(12, visible));
			for (Lifespan span : coordinates.getView().getViewport().getOrderedSpans()) {
				AddressSetView alreadyKnown =
					mm.getAddressesWithState(span.lmin(), visible,
						s -> s == TraceMemoryState.KNOWN);
				toRead.delete(alreadyKnown);
				if (span.lmax() != span.lmin() || toRead.isEmpty()) {
					break;
				}
			}

			if (toRead.isEmpty()) {
				return CompletableFuture.completedFuture(false);
			}

			long snap = coordinates.getSnap();
			ByteBuffer buf = ByteBuffer.allocate(4096);
			try (Transaction tx = trace.openTransaction("Load Visible")) {
				new AbstractMappedMemoryBytesVisitor(mappingService, buf.array()) {
					@Override
					protected void visitData(Address hostAddr, byte[] data, int size) {
						buf.position(0);
						buf.limit(size);
						mm.putBytes(snap, hostAddr, buf);
					}
				}.visit(trace, snap, toRead);
				return CompletableFuture.completedFuture(true);
			}
			catch (MemoryAccessException e) {
				throw new AssertionError(e);
			}
		}
	};

	private final String configName;
	private final String menuName;
	private final Icon menuIcon;

	private BasicAutoReadMemorySpec(String configName, String menuName, Icon menuIcon) {
		this.configName = configName;
		this.menuName = menuName;
		this.menuIcon = menuIcon;
	}

	@Override
	public String getConfigName() {
		return configName;
	}

	@Override
	public String getMenuName() {
		return menuName;
	}

	@Override
	public Icon getMenuIcon() {
		return menuIcon;
	}

	@Override
	public AutoReadMemorySpec getEffective(DebuggerCoordinates coordinates) {
		Trace trace = coordinates.getTrace();
		if (trace != null && ProgramEmulationUtils.isEmulatedProgram(trace)) {
			return LOAD_EMULATOR;
		}
		return this;
	}

	/**
	 * A convenience for performing target memory reads with progress displayed
	 * 
	 * @param tool the tool for displaying progress
	 * @param reader the method to perform the read, asynchronously
	 * @return a future which returns true if the read completes
	 */
	protected CompletableFuture<Boolean> doRead(PluginTool tool,
			Function<TaskMonitor, CompletableFuture<Void>> reader) {
		return TargetActionTask
				.executeTask(tool, getMenuName(), true, true, false, m -> reader.apply(m))
				.thenApply(__ -> true);
	}
}
