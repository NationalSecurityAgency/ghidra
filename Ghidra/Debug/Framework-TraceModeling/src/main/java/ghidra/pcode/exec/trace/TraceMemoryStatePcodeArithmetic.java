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

import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.opbehavior.BinaryOpBehavior;
import ghidra.pcode.opbehavior.UnaryOpBehavior;
import ghidra.trace.model.memory.TraceMemoryState;

public enum TraceMemoryStatePcodeArithmetic implements PcodeArithmetic<TraceMemoryState> {
	INSTANCE;

	@Override
	public TraceMemoryState unaryOp(UnaryOpBehavior op, int sizeout, int sizein,
			TraceMemoryState in1) {
		return in1;
	}

	@Override
	public TraceMemoryState binaryOp(BinaryOpBehavior op, int sizeout, int sizein,
			TraceMemoryState in1, TraceMemoryState in2) {
		if (in1 == TraceMemoryState.KNOWN && in2 == TraceMemoryState.KNOWN) {
			return TraceMemoryState.KNOWN;
		}
		return TraceMemoryState.UNKNOWN;
	}

	@Override
	public TraceMemoryState fromConst(long value, int size) {
		return TraceMemoryState.KNOWN;
	}

	@Override
	public TraceMemoryState fromConst(BigInteger value, int size) {
		return TraceMemoryState.KNOWN;
	}

	@Override
	public boolean isTrue(TraceMemoryState cond) {
		throw new AssertionError("Cannot decide branches using TraceMemoryState");
	}

	@Override
	public BigInteger toConcrete(TraceMemoryState value) {
		throw new AssertionError("Cannot make TraceMemoryState a 'concrete value'");
	}
}
