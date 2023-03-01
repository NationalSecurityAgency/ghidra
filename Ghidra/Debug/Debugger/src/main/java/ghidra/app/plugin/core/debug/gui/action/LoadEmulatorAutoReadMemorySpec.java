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
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.AutoReadMemoryAction;
import ghidra.app.plugin.core.debug.service.emulation.ProgramEmulationUtils;
import ghidra.app.plugin.core.debug.service.model.record.RecorderUtils;
import ghidra.app.plugin.core.debug.utils.AbstractMappedMemoryBytesVisitor;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.async.AsyncUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemoryManager;
import ghidra.trace.model.memory.TraceMemoryState;

public class LoadEmulatorAutoReadMemorySpec implements AutoReadMemorySpec {
	public static final String CONFIG_NAME = "LOAD_EMULATOR";

	@Override
	public String getConfigName() {
		return CONFIG_NAME;
	}

	@Override
	public String getMenuName() {
		return AutoReadMemoryAction.NAME_LOAD_EMU;
	}

	@Override
	public Icon getMenuIcon() {
		return AutoReadMemoryAction.ICON_LOAD_EMU;
	}

	@Override
	public CompletableFuture<?> readMemory(PluginTool tool, DebuggerCoordinates coordinates,
			AddressSetView visible) {
		DebuggerStaticMappingService mappingService =
			tool.getService(DebuggerStaticMappingService.class);
		if (mappingService == null) {
			return AsyncUtils.NIL;
		}
		Trace trace = coordinates.getTrace();
		if (trace == null || coordinates.isAlive() ||
			!ProgramEmulationUtils.isEmulatedProgram(trace)) {
			// Never interfere with a live target
			return AsyncUtils.NIL;
		}
		TraceMemoryManager mm = trace.getMemoryManager();
		AddressSet toRead = new AddressSet(RecorderUtils.INSTANCE.quantize(12, visible));
		for (Lifespan span : coordinates.getView().getViewport().getOrderedSpans()) {
			AddressSetView alreadyKnown =
				mm.getAddressesWithState(span.lmin(), visible, s -> s == TraceMemoryState.KNOWN);
			toRead.delete(alreadyKnown);
			if (span.lmax() != span.lmin() || toRead.isEmpty()) {
				break;
			}
		}

		if (toRead.isEmpty()) {
			return AsyncUtils.NIL;
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
			return AsyncUtils.NIL;
		}
		catch (MemoryAccessException e) {
			throw new AssertionError(e);
		}
	}
}
