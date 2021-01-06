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
package ghidra.app.plugin.core.debug.service.emulation;

import java.util.concurrent.*;

import com.google.common.collect.Range;
import com.google.common.primitives.UnsignedLong;

import ghidra.app.services.TraceRecorder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.exec.AccessPcodeExecutionException;
import ghidra.pcode.exec.trace.TraceCachedWriteBytesPcodeExecutorState;
import ghidra.pcode.exec.trace.TraceSleighUtils;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.database.UndoableTransaction;

public abstract class AbstractReadsTargetPcodeExecutorState
		extends TraceCachedWriteBytesPcodeExecutorState {

	abstract class AbstractReadsTargetCachedSpace extends CachedSpace {
		public AbstractReadsTargetCachedSpace(AddressSpace space,
				TraceMemorySpace source, long snap) {
			super(space, source, snap);
		}

		protected abstract void fillUninitialized(AddressSet uninitialized);

		protected boolean isLive() {
			return recorder != null && recorder.isRecording() && recorder.getSnap() == snap;
		}

		protected AddressSet computeUnknown(AddressSet uninitialized) {
			return uninitialized.subtract(source.getAddressesWithState(snap, uninitialized,
				s -> s != null && s != TraceMemoryState.UNKNOWN));
		}

		@Override
		public byte[] read(long offset, int size) {
			if (source != null) {
				AddressSet uninitialized = new AddressSet();
				for (Range<UnsignedLong> rng : cache.getUninitialized(offset, offset + size)
						.asRanges()) {
					uninitialized.add(space.getAddress(lower(rng)),
						space.getAddress(upper(rng)));
				}
				if (uninitialized.isEmpty()) {
					return super.read(offset, size);
				}

				fillUninitialized(uninitialized);
			}

			// TODO: What to flush when bytes in the trace change?
			return super.read(offset, size);
		}

		protected <T> T waitTimeout(CompletableFuture<T> future) {
			try {
				return future.get(1, TimeUnit.SECONDS);
			}
			catch (InterruptedException | ExecutionException | TimeoutException e) {
				throw new AccessPcodeExecutionException("Timed out reading target", e);
			}
		}
	}

	protected final TraceRecorder recorder;
	protected final PluginTool tool;

	public AbstractReadsTargetPcodeExecutorState(PluginTool tool, Trace trace, long snap,
			TraceThread thread, int frame, TraceRecorder recorder) {
		super(trace, snap, thread, frame);
		this.tool = tool;
		this.recorder = recorder;
	}

	protected abstract AbstractReadsTargetCachedSpace createCachedSpace(AddressSpace s,
			TraceMemorySpace tms);

	@Override
	protected CachedSpace getForSpace(AddressSpace space, boolean toWrite) {
		return spaces.computeIfAbsent(space, s -> {
			TraceMemorySpace tms;
			if (s.isUniqueSpace()) {
				tms = null;
			}
			else {
				try (UndoableTransaction tid =
					UndoableTransaction.start(trace, "Create space", true)) {
					tms = TraceSleighUtils.getSpaceForExecution(s, trace, thread, frame, true);
				}
			}
			return createCachedSpace(s, tms);
		});
	}
}
