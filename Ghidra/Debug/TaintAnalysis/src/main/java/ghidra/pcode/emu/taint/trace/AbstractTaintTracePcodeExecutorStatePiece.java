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
package ghidra.pcode.emu.taint.trace;

import ghidra.pcode.emu.taint.AbstractTaintPcodeExecutorStatePiece;
import ghidra.pcode.emu.taint.TaintPcodeArithmetic;
import ghidra.pcode.exec.BytesPcodeArithmetic;
import ghidra.pcode.exec.trace.TracePcodeExecutorStatePiece;
import ghidra.program.model.lang.Language;
import ghidra.taint.model.TaintVec;
import ghidra.trace.model.Trace;
import ghidra.trace.model.property.TracePropertyMap;
import ghidra.trace.model.thread.TraceThread;

/**
 * An abstract trace-integrated state piece
 *
 * <p>
 * See {@link AbstractTaintTracePcodeExecutorStatePiece} for framing. This class must remain
 * abstract since we need to derive the Debugger-integrated state piece from it. Thus it tightens
 * the bound on {@code <S>} and introduces the parameters necessary to source state from a trace.
 * We'll store taint sets in the trace's address property map, which is the recommended scheme for
 * auxiliary state.
 *
 * @param <S> the type of spaces
 */
public abstract class AbstractTaintTracePcodeExecutorStatePiece<S extends TaintTraceSpace>
		extends AbstractTaintPcodeExecutorStatePiece<S>
		implements TracePcodeExecutorStatePiece<byte[], TaintVec> {
	public static final String NAME = "Taint";

	protected final Trace trace;
	protected final long snap;
	protected final TraceThread thread;
	protected final int frame;
	protected final TracePropertyMap<String> map;

	/**
	 * Create a state piece
	 * 
	 * @param language the emulator's language
	 * @param trace the trace from which to load taint marks
	 * @param snap the snap from which to load taint marks
	 * @param thread if a register space, the thread from which to load taint marks
	 * @param frame if a register space, the frame
	 */
	public AbstractTaintTracePcodeExecutorStatePiece(Language language, Trace trace, long snap,
			TraceThread thread, int frame) {
		super(language,
			BytesPcodeArithmetic.forLanguage(language),
			TaintPcodeArithmetic.forLanguage(language));
		this.trace = trace;
		this.snap = snap;
		this.thread = thread;
		this.frame = frame;

		this.map = trace.getAddressPropertyManager().getPropertyMap(NAME, String.class);
	}

	/**
	 * Create a state piece
	 * 
	 * @param trace the trace from which to load taint marks
	 * @param snap the snap from which to load taint marks
	 * @param thread if a register space, the thread from which to load taint marks
	 * @param frame if applicable, the frame
	 */
	public AbstractTaintTracePcodeExecutorStatePiece(Trace trace, long snap, TraceThread thread,
			int frame) {
		this(trace.getBaseLanguage(), trace, snap, thread, frame);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * This does the inverse of the lazy loading. Serialize the state and store it back into the
	 * trace. Technically, it could be a different trace, but it must have identically-named
	 * threads.
	 */
	@Override
	public void writeDown(Trace trace, long snap, TraceThread thread, int frame) {
		TracePropertyMap<String> map =
			trace.getAddressPropertyManager().getOrCreatePropertyMap(NAME, String.class);
		for (TaintTraceSpace space : spaceMap.values()) {
			space.writeDown(map, snap, thread, frame);
		}
	}
}
