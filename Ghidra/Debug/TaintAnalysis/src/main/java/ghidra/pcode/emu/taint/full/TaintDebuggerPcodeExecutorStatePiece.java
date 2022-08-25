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
package ghidra.pcode.emu.taint.full;

import ghidra.app.services.TraceRecorder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.emu.taint.trace.*;
import ghidra.program.model.address.AddressSpace;
import ghidra.trace.model.Trace;
import ghidra.trace.model.property.TracePropertyMapSpace;
import ghidra.trace.model.thread.TraceThread;

/**
 * The Debugger-integrated state piece for holding taint marks
 * 
 * <p>
 * Because we don't require a derivative of this class, it is not split into abstract and
 * non-abstract classes (like its super-classes were). This substitutes {@link TaintDebuggerSpace}
 * for {@link TaintTraceSpace} and introduces parameters for loading information from mapped static
 * programs. We take the recorder more as a matter of form, since we don't really need it.
 */
public class TaintDebuggerPcodeExecutorStatePiece
		extends AbstractTaintTracePcodeExecutorStatePiece<TaintDebuggerSpace> {

	protected final PluginTool tool;
	protected final TraceRecorder recorder;

	/**
	 * Create the taint piece
	 * 
	 * @param tool the tool that created the emulator
	 * @param trace the trace from which to load taint marks
	 * @param snap the snap from which to load taint marks
	 * @param thread if a register space, the thread from which to load taint marks
	 * @param frame if a register space, the frame
	 * @param recorder if applicable, the recorder for the trace's live target
	 */
	public TaintDebuggerPcodeExecutorStatePiece(PluginTool tool, Trace trace, long snap,
			TraceThread thread, int frame, TraceRecorder recorder) {
		super(trace, snap, thread, frame);
		this.tool = tool;
		this.recorder = recorder;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Here we create a map that uses {@link TaintDebuggerSpace}s. There is some repeated code with
	 * {@link TaintTracePcodeExecutorStatePiece#newSpaceMap()}. We could factor that, but I thought
	 * it a little pedantic.
	 */
	@Override
	protected AbstractSpaceMap<TaintDebuggerSpace> newSpaceMap() {
		return new CacheingSpaceMap<TracePropertyMapSpace<String>, TaintDebuggerSpace>() {
			@Override
			protected TracePropertyMapSpace<String> getBacking(AddressSpace space) {
				if (map == null) {
					return null;
				}
				if (space.isRegisterSpace()) {
					return map.getPropertyMapRegisterSpace(thread, frame, false);
				}
				return map.getPropertyMapSpace(space, false);
			}

			@Override
			protected TaintDebuggerSpace newSpace(AddressSpace space,
					TracePropertyMapSpace<String> backing) {
				return new TaintDebuggerSpace(tool, trace, space, backing, snap);
			}
		};
	}
}
