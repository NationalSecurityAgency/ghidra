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
package ghidra.pcode.exec.trace.data;

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang3.tuple.Pair;

import ghidra.pcode.emu.PcodeThread;
import ghidra.program.model.lang.Language;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceTimeViewport;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.thread.TraceThread;

/**
 * An abstract implementation of {@link PcodeTraceAccess}
 * 
 * @param <S> the type of shared data-access shims provided
 * @param <L> the type of thread-local data-access shims provided
 */
public abstract class AbstractPcodeTraceAccess<S extends PcodeTraceMemoryAccess, L extends PcodeTraceRegistersAccess>
		implements PcodeTraceAccess {

	protected final TracePlatform platform;
	protected final long threadsSnap;
	protected final long snap;

	protected final TraceTimeViewport viewport;
	protected S dataForSharedState;
	protected final Map<Pair<TraceThread, Integer>, L> dataForLocalStateByThreadAndFrame =
		new HashMap<>();

	/**
	 * Construct a shim
	 * 
	 * @param platform the associated platform
	 * @param snap the associated snap
	 * @param threadsSnap the snap to use when finding associated threads between trace and emulator
	 */
	public AbstractPcodeTraceAccess(TracePlatform platform, long snap, long threadsSnap) {
		this.platform = platform;
		this.snap = snap;
		this.threadsSnap = threadsSnap;

		TraceTimeViewport viewport = getTrace().createTimeViewport();
		viewport.setSnap(snap);
		this.viewport = viewport;
	}

	/**
	 * Construct a shim
	 * 
	 * @param platform the associated platform
	 * @param snap the associated snap
	 */
	public AbstractPcodeTraceAccess(TracePlatform platform, long snap) {
		this(platform, snap, snap);
	}

	/**
	 * Get the associated trace
	 * 
	 * @return the trace
	 */
	protected Trace getTrace() {
		return platform.getTrace();
	}

	/**
	 * Get the trace thread conventionally associated with the given p-code thread
	 * 
	 * <p>
	 * A p-code thread is conventionally associated with the trace thread whose path matches the
	 * p-code thread's name.
	 * 
	 * @param thread the p-code thread
	 * @return the trace thread
	 */
	protected TraceThread getTraceThread(PcodeThread<?> thread) {
		return getTrace().getThreadManager().getLiveThreadByPath(threadsSnap, thread.getName());
	}

	@Override
	public Language getLanguage() {
		return platform.getLanguage();
	}

	/**
	 * Factory method for the shared data-access shim
	 * 
	 * @return the new data-access shim
	 */
	protected abstract S newDataForSharedState();

	@Override
	public S getDataForSharedState() {
		synchronized (dataForLocalStateByThreadAndFrame) {
			if (dataForSharedState == null) {
				dataForSharedState = newDataForSharedState();
			}
			return dataForSharedState;
		}
	}

	/**
	 * Factory method for a thread's local data-access shim
	 * 
	 * @param thread the associated trace thread
	 * @param frame the frame, usually 0
	 * @return the new data-access shim
	 */
	protected abstract L newDataForLocalState(TraceThread thread, int frame);

	@Override
	public L getDataForLocalState(TraceThread thread, int frame) {
		if (thread == null) {
			return null;
		}
		synchronized (dataForLocalStateByThreadAndFrame) {
			return dataForLocalStateByThreadAndFrame.computeIfAbsent(Pair.of(thread, frame), p -> {
				return newDataForLocalState(p.getLeft(), p.getRight());
			});
		}
	}

	@Override
	public L getDataForLocalState(PcodeThread<?> thread, int frame) {
		return getDataForLocalState(getTraceThread(thread), frame);
	}
}
