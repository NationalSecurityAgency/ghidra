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

import java.math.BigInteger;

import ghidra.pcode.exec.ConcretionError;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.opbehavior.BinaryOpBehavior;
import ghidra.program.model.lang.Endian;
import ghidra.trace.model.memory.TraceMemoryState;

/**
 * The p-code arithmetic for {@link TraceMemoryState}
 * 
 * <p>
 * This arithmetic is meant to be used as an auxiliary to a concrete arithmetic. It should be used
 * with a state that knows how to load state markings from the same trace as the concrete state, so
 * that it can compute the "state" of a Sleigh expression's value. It essentially works like a
 * rudimentary taint analyzer: If any part of any input to the expression in tainted, i.e., not
 * {@link TraceMemoryState#KNOWN}, then the result is {@link TraceMemoryState#UNKNOWN}. This is best
 * exemplified in
 * {@link #binaryOp(BinaryOpBehavior, int, int, TraceMemoryState, int, TraceMemoryState)}.
 */
public enum TraceMemoryStatePcodeArithmetic implements PcodeArithmetic<TraceMemoryState> {
	/** The singleton instance */
	INSTANCE;

	@Override
	public Endian getEndian() {
		return null;
	}

	@Override
	public TraceMemoryState unaryOp(int opcode, int sizeout, int sizein1,
			TraceMemoryState in1) {
		return in1;
	}

	@Override
	public TraceMemoryState binaryOp(int opcode, int sizeout, int sizein1,
			TraceMemoryState in1, int sizein2, TraceMemoryState in2) {
		if (in1 == TraceMemoryState.KNOWN && in2 == TraceMemoryState.KNOWN) {
			return TraceMemoryState.KNOWN;
		}
		return TraceMemoryState.UNKNOWN;
	}

	@Override
	public TraceMemoryState modBeforeStore(int sizeout, int sizeinAddress,
			TraceMemoryState inAddress, int sizeinValue, TraceMemoryState inValue) {
		return inValue; // Shouldn't see STORE during Sleigh eval, anyway
	}

	@Override
	public TraceMemoryState modAfterLoad(int sizeout, int sizeinAddress, TraceMemoryState inAddress,
			int sizeinValue, TraceMemoryState inValue) {
		if (inAddress == TraceMemoryState.KNOWN && inValue == TraceMemoryState.KNOWN) {
			return TraceMemoryState.KNOWN;
		}
		return TraceMemoryState.UNKNOWN;
	}

	@Override
	public TraceMemoryState fromConst(byte[] value) {
		return TraceMemoryState.KNOWN;
	}

	@Override
	public TraceMemoryState fromConst(BigInteger value, int size, boolean isContextreg) {
		return TraceMemoryState.KNOWN;
	}

	@Override
	public TraceMemoryState fromConst(long value, int size) {
		return TraceMemoryState.KNOWN;
	}

	@Override
	public byte[] toConcrete(TraceMemoryState value, Purpose purpose) {
		throw new ConcretionError("Cannot make TraceMemoryState concrete", purpose);
	}

	@Override
	public long sizeOf(TraceMemoryState value) {
		throw new AssertionError("Cannot get size of a TraceMemoryState");
	}
}
