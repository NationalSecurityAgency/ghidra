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
package ghidra.pcode.exec.trace;

import ghidra.pcode.emu.*;
import ghidra.pcode.exec.trace.data.*;
import ghidra.trace.model.guest.TracePlatform;

/**
 * An emulator that can read initial state from a trace and record its state back into it
 */
public class BytesTracePcodeEmulator extends PcodeEmulator implements TracePcodeMachine<byte[]> {
	protected final PcodeTraceAccess access;

	/**
	 * Create a trace-bound emulator
	 * 
	 * @param access the trace access shim
	 */
	public BytesTracePcodeEmulator(PcodeTraceAccess access) {
		super(access.getLanguage());
		this.access = access;
	}

	/**
	 * Create a trace-bound emulator
	 * 
	 * @param platform the platform to emulate
	 * @param snap the source snap
	 */
	public BytesTracePcodeEmulator(TracePlatform platform, long snap) {
		this(new DefaultPcodeTraceAccess(platform, snap));
	}

	@Override
	protected BytesPcodeThread createThread(String name) {
		BytesPcodeThread thread = super.createThread(name);
		access.getDataForLocalState(thread, 0).initializeThreadContext(thread);
		return thread;
	}

	protected TracePcodeExecutorState<byte[]> newState(PcodeTraceDataAccess data) {
		return new BytesTracePcodeExecutorState(data);
	}

	@Override
	public TracePcodeExecutorState<byte[]> createSharedState() {
		return newState(access.getDataForSharedState());
	}

	@Override
	public TracePcodeExecutorState<byte[]> createLocalState(PcodeThread<byte[]> thread) {
		return newState(access.getDataForLocalState(thread, 0));
	}
}
