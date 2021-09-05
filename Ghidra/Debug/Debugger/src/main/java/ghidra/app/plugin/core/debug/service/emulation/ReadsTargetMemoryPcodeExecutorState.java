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

import java.util.Map.Entry;

import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.services.DebuggerStaticMappingService.ShiftAndAddressSetView;
import ghidra.app.services.TraceRecorder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.MathUtilities;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class ReadsTargetMemoryPcodeExecutorState
		extends AbstractReadsTargetPcodeExecutorState {

	protected class ReadsTargetMemoryCachedSpace extends AbstractReadsTargetCachedSpace {

		public ReadsTargetMemoryCachedSpace(AddressSpace space, TraceMemorySpace source,
				long snap) {
			super(space, source, snap);
		}

		@Override
		protected void fillUninitialized(AddressSet uninitialized) {
			AddressSet unknown;
			unknown = computeUnknown(uninitialized);
			if (unknown.isEmpty()) {
				return;
			}
			if (fillUnknownWithRecorder(unknown)) {
				unknown = computeUnknown(uninitialized);
				if (unknown.isEmpty()) {
					return;
				}
			}
			if (fillUnknownWithStaticImages(unknown)) {
				unknown = computeUnknown(uninitialized);
				if (unknown.isEmpty()) {
					return;
				}
			}
			Msg.warn(this, "Emulator read from UNKNOWN state: " + unknown);
		}

		protected boolean fillUnknownWithRecorder(AddressSet unknown) {
			if (!isLive()) {
				return false;
			}
			waitTimeout(recorder.captureProcessMemory(unknown, TaskMonitor.DUMMY, false));
			return true;
		}

		private boolean fillUnknownWithStaticImages(AddressSet unknown) {
			boolean result = false;
			// TODO: Expand to block? DON'T OVERWRITE KNOWN!
			DebuggerStaticMappingService mappingService =
				tool.getService(DebuggerStaticMappingService.class);
			byte[] data = new byte[4096];
			for (Entry<Program, ShiftAndAddressSetView> ent : mappingService
					.getOpenMappedViews(trace, unknown, snap)
					.entrySet()) {
				Program program = ent.getKey();
				ShiftAndAddressSetView shifted = ent.getValue();
				long shift = shifted.getShift();
				Memory memory = program.getMemory();
				AddressSetView initialized = memory.getLoadedAndInitializedAddressSet();
				AddressSetView toRead = shifted.getAddressSetView().intersect(initialized);
				Msg.warn(this,
					"Filling in unknown trace memory in emulator using mapped image: " +
						program + ": " + toRead);

				for (AddressRange rng : toRead) {
					long lower = rng.getMinAddress().getOffset();
					long fullLen = rng.getLength();
					while (fullLen > 0) {
						int len = MathUtilities.unsignedMin(data.length, fullLen);
						try {
							int read =
								memory.getBytes(space.getAddress(lower), data, 0, len);
							if (read < len) {
								Msg.warn(this,
									"  Partial read of " + rng + ". Got " + read + " bytes");
							}
							cache.putData(lower - shift, data, 0, read);
						}
						catch (MemoryAccessException | AddressOutOfBoundsException e) {
							throw new AssertionError(e);
						}
						lower += len;
						fullLen -= len;
					}
					result = true;
				}
			}
			return result;
		}
	}

	public ReadsTargetMemoryPcodeExecutorState(PluginTool tool, Trace trace, long snap,
			TraceThread thread, int frame, TraceRecorder recorder) {
		super(tool, trace, snap, thread, frame, recorder);
	}

	@Override
	protected AbstractReadsTargetCachedSpace createCachedSpace(AddressSpace s,
			TraceMemorySpace tms) {
		return new ReadsTargetMemoryCachedSpace(s, tms, snap);
	}
}
