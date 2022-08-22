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

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import ghidra.app.services.TraceRecorder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.Msg;

/**
 * An executor state piece that knows to read live memory if applicable
 * 
 * <p>
 * This takes a handle to the trace's recorder, if applicable, and will check if the source snap is
 * the recorder's snap. If so, it will direct the recorder to capture the register to be read, if
 * it's not already {@link TraceMemoryState#KNOWN}. When such reads occur, the state will wait up to
 * 1 second (see {@link AbstractReadsTargetCachedSpace#waitTimeout(CompletableFuture)}).
 * 
 * <ol>
 * <li>The cache, i.e., this state object</li>
 * <li>The trace</li>
 * <li>The live target, if applicable</li>
 * </ol>
 * 
 * <p>
 * If all those defer, the state is read as if filled with 0s.
 */
public class ReadsTargetRegistersPcodeExecutorStatePiece
		extends AbstractReadsTargetPcodeExecutorStatePiece {

	/**
	 * A space, corresponding to a register space (really a thread) of this state
	 * 
	 * <p>
	 * All of the actual read logic is contained here. We override the space map factory so that it
	 * creates these spaces.
	 */
	protected class ReadsTargetRegistersCachedSpace extends AbstractReadsTargetCachedSpace {

		public ReadsTargetRegistersCachedSpace(Language language, AddressSpace space,
				TraceMemorySpace source, long snap) {
			super(language, space, source, snap);
		}

		@Override
		protected void fillUninitialized(AddressSet uninitialized) {
			if (!isLive()) {
				return;
			}
			AddressSet unknown = computeUnknown(uninitialized);
			Set<Register> toRead = new HashSet<>();
			for (AddressRange rng : unknown) {
				Register register =
					language.getRegister(rng.getMinAddress(), (int) rng.getLength());
				if (register == null) {
					Msg.error(this, "Could not figure register for " + rng);
				}
				else if (!recorder.getRegisterMapper(thread)
						.getRegistersOnTarget()
						.contains(register)) {
					Msg.warn(this, "Register not recognized by target: " + register);
				}
				else {
					toRead.add(register);
				}
			}
			waitTimeout(recorder.captureThreadRegisters(thread, 0, toRead));
		}
	}

	public ReadsTargetRegistersPcodeExecutorStatePiece(PluginTool tool, Trace trace, long snap,
			TraceThread thread, int frame, TraceRecorder recorder) {
		super(tool, trace, snap, thread, frame, recorder);
	}

	@Override
	protected AbstractSpaceMap<CachedSpace> newSpaceMap() {
		return new TargetBackedSpaceMap() {
			@Override
			protected CachedSpace newSpace(AddressSpace space, TraceMemorySpace backing) {
				return new ReadsTargetRegistersCachedSpace(language, space, backing, snap);
			}
		};
	}
}
