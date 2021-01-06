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

import ghidra.app.services.TraceRecorder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.Msg;

public class ReadsTargetRegistersPcodeExecutorState
		extends AbstractReadsTargetPcodeExecutorState {

	protected class ReadsTargetRegistersCachedSpace extends AbstractReadsTargetCachedSpace {

		public ReadsTargetRegistersCachedSpace(AddressSpace space, TraceMemorySpace source,
				long snap) {
			super(space, source, snap);
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

	public ReadsTargetRegistersPcodeExecutorState(PluginTool tool, Trace trace, long snap,
			TraceThread thread, int frame, TraceRecorder recorder) {
		super(tool, trace, snap, thread, frame, recorder);
	}

	@Override
	protected AbstractReadsTargetCachedSpace createCachedSpace(AddressSpace s,
			TraceMemorySpace tms) {
		return new ReadsTargetRegistersCachedSpace(s, tms, snap);
	}
}
