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
package ghidra.app.plugin.core.debug.service.emulation.data;

import ghidra.debug.api.modules.DebuggerAddressTranslator;
import ghidra.debug.api.target.Target;
import ghidra.pcode.exec.trace.data.DefaultPcodeTraceAccess;
import ghidra.pcode.exec.trace.data.PcodeTraceAccess;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.thread.TraceThread;

/**
 * The default target-and-trace access shim for a session with a provided
 * {@linkplain DebuggerAddressTranslator address translator}.
 */
public abstract class TranslatedPcodeDebuggerAccess extends AbstractPcodeDebuggerAccess<
	TranslatedPcodeDebuggerMemoryAccess, DefaultPcodeDebuggerRegistersAccess> {

	/**
	 * Construct a shim
	 * 
	 * @param target the target
	 * @param platform the associated platform, having the same trace as the recorder
	 * @param snap the associated snap
	 */
	public TranslatedPcodeDebuggerAccess(Target target,
			TracePlatform platform, long snap) {
		super(target, platform, snap);
	}

	/**
	 * Construct a shim
	 * 
	 * @param target the target
	 * @param platform the associated platform, having the same trace as the recorder
	 * @param snap the associated snap
	 * @param threadsSnap the snap to use when finding associated threads between trace and emulator
	 */
	public TranslatedPcodeDebuggerAccess(Target target, TracePlatform platform, long snap,
			long threadsSnap) {
		super(target, platform, snap, threadsSnap);
	}

	/**
	 * {@return the address translator or null. If null is returned, then bytes cannot be loaded
	 * from mapped images.}
	 * 
	 * @see InternalPcodeDebuggerDataAccess#getAddressTranslator()
	 */
	public abstract DebuggerAddressTranslator getAddressTranslator();

	/**
	 * {@inheritDoc}
	 * 
	 * @implNote This does <em>not</em> return a Debugger access shim, but a Trace one, since we
	 *           never expect a delayed write to affect the target.
	 */
	@Override
	public PcodeTraceAccess deriveForWrite(long snap) {
		return new DefaultPcodeTraceAccess(platform, snap, threadsSnap);
	}

	@Override
	protected TranslatedPcodeDebuggerMemoryAccess newDataForSharedState() {
		return new TranslatedPcodeDebuggerMemoryAccess(target, platform, snap, viewport) {
			@Override
			public DebuggerAddressTranslator getAddressTranslator() {
				return TranslatedPcodeDebuggerAccess.this.getAddressTranslator();
			}
		};
	}

	@Override
	protected DefaultPcodeDebuggerRegistersAccess newDataForLocalState(TraceThread thread,
			int frame) {
		return new DefaultPcodeDebuggerRegistersAccess(target, platform, snap, thread, frame,
			viewport);
	}
}
