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
package ghidra.pcode.emu.symz3.trace;

import java.util.Collection;

import ghidra.pcode.emu.symz3.*;
import ghidra.pcode.emu.symz3.plain.SymZ3PcodeEmulator;
import ghidra.pcode.exec.trace.auxiliary.AuxTraceEmulatorPartsFactory;
import ghidra.pcode.exec.trace.auxiliary.AuxTracePcodeEmulator;
import ghidra.pcode.exec.trace.data.PcodeTraceAccess;
import ghidra.symz3.model.SymValueZ3;
import ghidra.trace.model.guest.TracePlatform;

/**
 * A trace-integrated emulator with symbolic value analysis
 */
public class SymZ3TracePcodeEmulator extends AuxTracePcodeEmulator<SymValueZ3>
		implements SymZ3PcodeEmulatorTrait {
	/**
	 * Create an emulator
	 * 
	 * @param access the trace access shim
	 */
	public SymZ3TracePcodeEmulator(PcodeTraceAccess access) {
		super(access);
	}

	public SymZ3TracePcodeEmulator(TracePlatform platform, long snap) {
		super(platform, snap);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Here, we just return the singleton parts factory. This appears simple because all the
	 * complexity is encapsulated in the factory. See {@link SymZ3PartsFactory} to see everything
	 * the implementation actually entails. Notice that this is the same parts factory used by
	 * {@link SymZ3PcodeEmulator}. The {@link AuxTracePcodeEmulator} knows to use the more capable
	 * state parts.
	 */
	@Override
	protected AuxTraceEmulatorPartsFactory<SymValueZ3> getPartsFactory() {
		return SymZ3PartsFactory.INSTANCE;
	}

	@Override
	public SymZ3PcodeThread newThread() {
		return (SymZ3PcodeThread) super.newThread();
	}

	@Override
	public SymZ3PcodeThread newThread(String name) {
		return (SymZ3PcodeThread) super.newThread(name);
	}

	@Override
	@SuppressWarnings("unchecked")
	public Collection<? extends SymZ3PcodeThread> getAllThreads() {
		return (Collection<? extends SymZ3PcodeThread>) super.getAllThreads();
	}

	@Override
	public SymZ3PairedPcodeExecutorState getSharedState() {
		return (SymZ3PairedPcodeExecutorState) super.getSharedState();
	}
}
