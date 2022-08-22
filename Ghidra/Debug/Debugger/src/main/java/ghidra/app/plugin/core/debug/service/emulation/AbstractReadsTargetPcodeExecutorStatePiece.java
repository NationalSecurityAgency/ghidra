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

import ghidra.app.services.TraceRecorder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.exec.AccessPcodeExecutionException;
import ghidra.pcode.exec.trace.BytesTracePcodeExecutorStatePiece;
import ghidra.pcode.exec.trace.TraceSleighUtils;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.database.UndoableTransaction;

/**
 * An executor state piece that knows to read live state if applicable
 *
 * <p>
 * This takes a handle to the trace's recorder, if applicable, and will check if the source snap is
 * the recorder's snap. If so, it will direct the recorder to capture the desired state, if they're
 * not already {@link TraceMemoryState#KNOWN}. When such reads occur, the state will wait up to 1
 * second (see {@link AbstractReadsTargetCachedSpace#waitTimeout(CompletableFuture)}).
 */
public abstract class AbstractReadsTargetPcodeExecutorStatePiece
		extends BytesTracePcodeExecutorStatePiece {

	abstract class AbstractReadsTargetCachedSpace extends CachedSpace {
		public AbstractReadsTargetCachedSpace(Language language, AddressSpace space,
				TraceMemorySpace backing, long snap) {
			super(language, space, backing, snap);
		}

		protected abstract void fillUninitialized(AddressSet uninitialized);

		protected boolean isLive() {
			return recorder != null && recorder.isRecording() && recorder.getSnap() == snap;
		}

		protected AddressSet computeUnknown(AddressSet uninitialized) {
			return uninitialized.subtract(backing.getAddressesWithState(snap, uninitialized,
				s -> s != null && s != TraceMemoryState.UNKNOWN));
		}

		@Override
		public byte[] read(long offset, int size) {
			if (backing != null) {
				AddressSet uninitialized =
					addrSet(bytes.getUninitialized(offset, offset + size - 1));
				if (uninitialized.isEmpty()) {
					return super.read(offset, size);
				}

				fillUninitialized(uninitialized);

				AddressSet unknown =
					computeUnknown(addrSet(bytes.getUninitialized(offset, offset + size - 1)));
				if (!unknown.isEmpty()) {
					warnUnknown(unknown);
				}
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

	public AbstractReadsTargetPcodeExecutorStatePiece(PluginTool tool, Trace trace, long snap,
			TraceThread thread, int frame, TraceRecorder recorder) {
		super(trace, snap, thread, frame);
		this.tool = tool;
		this.recorder = recorder;
	}

	/**
	 * Get the tool that manages this state's emulator.
	 * 
	 * <p>
	 * This is necessary to obtain the static mapping service, in case memory should be filled from
	 * static images.
	 * 
	 * @return the tool
	 */
	public PluginTool getTool() {
		return tool;
	}

	/**
	 * Get the recorder associated with the trace
	 * 
	 * @return this is used to check for and perform live reads
	 */
	public TraceRecorder getRecorder() {
		return recorder;
	}

	/**
	 * A partially implemented space map which retrieves "backing" objects from the trace's memory
	 * and register spaces.
	 */
	protected abstract class TargetBackedSpaceMap
			extends CacheingSpaceMap<TraceMemorySpace, CachedSpace> {
		@Override
		protected TraceMemorySpace getBacking(AddressSpace space) {
			try (UndoableTransaction tid =
				UndoableTransaction.start(trace, "Create space")) {
				return TraceSleighUtils.getSpaceForExecution(space, trace, thread, frame, true);
			}
		}
	}
}
