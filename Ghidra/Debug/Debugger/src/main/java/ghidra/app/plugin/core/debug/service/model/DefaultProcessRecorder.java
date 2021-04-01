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
package ghidra.app.plugin.core.debug.service.model;

import java.util.concurrent.CompletableFuture;

import ghidra.app.plugin.core.debug.mapping.DebuggerMemoryMapper;
import ghidra.app.plugin.core.debug.service.model.interfaces.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.trace.model.Trace;
import ghidra.util.TriConsumer;

public class DefaultProcessRecorder implements ManagedProcessRecorder {

	private final AbstractRecorderMemory processMemory;
	protected final TriConsumer<Boolean, Boolean, Void> listenerProcMemAccChanged =
		this::processMemoryAccessibilityChanged;

	private DefaultBreakpointRecorder breakpointRecorder;
	private DefaultTraceRecorder recorder;

	public DefaultProcessRecorder(DefaultTraceRecorder recorder) {
		this.recorder = recorder;
		this.processMemory = new RecorderSimpleMemory();
		//this.processMemory = new RecorderComposedMemory(this.getProcessMemory());

		//getProcessMemory().getMemAccListeners().add(listenerProcMemAccChanged);

		this.breakpointRecorder = new DefaultBreakpointRecorder(recorder);

	}

	protected void processMemoryAccessibilityChanged(boolean old,
			boolean acc, Void __) {
		recorder.getListeners().fire.processMemoryAccessibilityChanged(recorder);
	}

	public CompletableFuture<byte[]> readProcessMemory(Address start, int length) {
		Address tStart = recorder.getMemoryMapper().traceToTarget(start);
		return getProcessMemory().readMemory(tStart, length);
	}

	public CompletableFuture<Void> writeProcessMemory(Address start, byte[] data) {
		Address tStart = recorder.getMemoryMapper().traceToTarget(start);
		return getProcessMemory().writeMemory(tStart, data);
	}

	public AddressSetView getAccessibleProcessMemory() {
		// TODO: Efficiently distinguish which memory is process vs. thread
		///TODO Is this correct?
		return getProcessMemory().getAccessibleMemory(mem -> true, recorder.getMemoryMapper());
	}

	@Override
	public AbstractRecorderMemory getProcessMemory() {
		return processMemory;
	}

	@Override
	public ManagedBreakpointRecorder getBreakpointRecorder() {
		return breakpointRecorder;
	}

	@Override
	public Trace getTrace() {
		return recorder.trace;
	}

	@Override
	public long getSnap() {
		return recorder.getSnap();
	}

	@Override
	public DebuggerMemoryMapper getMemoryMapper() {
		return recorder.getMemoryMapper();
	}

}
