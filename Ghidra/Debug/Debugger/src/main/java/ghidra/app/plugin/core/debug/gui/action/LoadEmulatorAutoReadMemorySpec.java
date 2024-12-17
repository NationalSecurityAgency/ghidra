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
import java.util.concurrent.CompletableFuture;

import javax.swing.Icon;

import db.Transaction;
import ghidra.app.plugin.core.debug.service.emulation.ProgramEmulationUtils;
import ghidra.app.plugin.core.debug.utils.AbstractMappedMemoryBytesVisitor;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemoryManager;
import ghidra.trace.model.memory.TraceMemoryState;

enum LoadEmulatorAutoReadMemorySpec implements AutoReadMemorySpec {
	INSTANCE;

	@Override
	public String getConfigName() {
		return null;
	}

	@Override
	public String getMenuName() {
		return null;
	}

	@Override
	public Icon getMenuIcon() {
		return null;
	}

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
	public CompletableFuture<Boolean> readMemory(PluginTool tool, DebuggerCoordinates coordinates,
			AddressSetView visible) {
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
				mm.getAddressesWithState(span.lmin(), visible, s -> s == TraceMemoryState.KNOWN);
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
}
