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
import java.util.Map.Entry;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.exec.*;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.thread.TraceThread;

public enum TraceSleighUtils {
	;

	public static TraceMemorySpace getSpaceForExecution(AddressSpace space, Trace trace,
			TraceThread thread, int frame, boolean toWrite) {
		if (space.isRegisterSpace()) {
			if (thread == null) {
				throw new IllegalArgumentException(
					"Cannot access register unless a thread is given.");
			}
			return trace.getMemoryManager().getMemoryRegisterSpace(thread, frame, toWrite);
		}
		return trace.getMemoryManager().getMemorySpace(space, toWrite);
	}

	public static PcodeExecutor<byte[]> buildByteExecutor(Trace trace, long snap,
			TraceThread thread, int frame) {
		TraceBytesPcodeExecutorState state =
			new TraceBytesPcodeExecutorState(trace, snap, thread, frame);
		Language language = trace.getBaseLanguage();
		if (!(language instanceof SleighLanguage)) {
			throw new IllegalArgumentException("Trace must use a SLEIGH language");
		}
		return new PcodeExecutor<>((SleighLanguage) language,
			BytesPcodeArithmetic.forLanguage(language), state);
	}

	public static PcodeExecutor<Pair<byte[], TraceMemoryState>> buildByteWithStateExecutor(
			Trace trace, long snap, TraceThread thread, int frame) {
		TraceBytesPcodeExecutorState state =
			new TraceBytesPcodeExecutorState(trace, snap, thread, frame);
		PcodeExecutorState<Pair<byte[], TraceMemoryState>> paired = state.withMemoryState();
		Language language = trace.getBaseLanguage();
		if (!(language instanceof SleighLanguage)) {
			throw new IllegalArgumentException("Trace must use a SLEIGH language");
		}
		return new PcodeExecutor<>((SleighLanguage) language, new PairedPcodeArithmetic<>(
			BytesPcodeArithmetic.forLanguage(language), TraceMemoryStatePcodeArithmetic.INSTANCE),
			paired);
	}

	public static byte[] evaluateBytes(SleighExpression expr, Trace trace, long snap,
			TraceThread thread, int frame) {
		SleighLanguage language = expr.getLanguage();
		if (trace.getBaseLanguage() != language) {
			throw new IllegalArgumentException(
				"This expression can only be evaulated on traces with language " + language);
		}
		PcodeExecutor<byte[]> executor = buildByteExecutor(trace, snap, thread, frame);
		return expr.evaluate(executor);
	}

	public static BigInteger evaluate(SleighExpression expr, Trace trace, long snap,
			TraceThread thread, int frame) {
		byte[] bytes = evaluateBytes(expr, trace, snap, thread, frame);
		return Utils.bytesToBigInteger(bytes, bytes.length, expr.getLanguage().isBigEndian(),
			false);
	}

	public static Pair<byte[], TraceMemoryState> evaluateBytesWithState(SleighExpression expr,
			Trace trace, long snap, TraceThread thread, int frame) {
		SleighLanguage language = expr.getLanguage();
		if (trace.getBaseLanguage() != language) {
			throw new IllegalArgumentException(
				"This expression can only be evaulated on traces with language " +
					language);
		}
		PcodeExecutor<Pair<byte[], TraceMemoryState>> executor =
			buildByteWithStateExecutor(trace, snap, thread, frame);
		return expr.evaluate(executor);
	}

	public static Pair<BigInteger, TraceMemoryState> evaluateWithState(SleighExpression expr,
			Trace trace, long snap, TraceThread thread, int frame) {
		Pair<byte[], TraceMemoryState> bytesPair =
			evaluateBytesWithState(expr, trace, snap, thread, frame);
		byte[] bytes = bytesPair.getLeft();
		return new ImmutablePair<>(
			Utils.bytesToBigInteger(bytes, bytes.length, expr.getLanguage().isBigEndian(), false),
			bytesPair.getRight());
	}

	public static byte[] evaluateBytes(String expr, Trace trace, long snap, TraceThread thread,
			int frame) {
		Language language = trace.getBaseLanguage();
		if (!(language instanceof SleighLanguage)) {
			throw new IllegalArgumentException("Trace must use a sleigh-based language");
		}
		return evaluateBytes(
			SleighProgramCompiler.compileExpression((SleighLanguage) language, expr),
			trace, snap, thread, frame);
	}

	public static BigInteger evaluate(String expr, Trace trace, long snap, TraceThread thread,
			int frame) {
		Language language = trace.getBaseLanguage();
		if (!(language instanceof SleighLanguage)) {
			throw new IllegalArgumentException("Trace must use a sleigh-based language");
		}
		return evaluate(SleighProgramCompiler.compileExpression((SleighLanguage) language, expr),
			trace, snap, thread, frame);
	}

	public static Entry<byte[], TraceMemoryState> evaluateBytesWithState(String expr, Trace trace,
			long snap, TraceThread thread, int frame) {
		Language language = trace.getBaseLanguage();
		if (!(language instanceof SleighLanguage)) {
			throw new IllegalArgumentException("Trace must use a sleigh-based language");
		}
		return evaluateBytesWithState(
			SleighProgramCompiler.compileExpression((SleighLanguage) language, expr),
			trace, snap, thread, frame);
	}

	public static Entry<BigInteger, TraceMemoryState> evaluateWithState(String expr, Trace trace,
			long snap, TraceThread thread, int frame) {
		Language language = trace.getBaseLanguage();
		if (!(language instanceof SleighLanguage)) {
			throw new IllegalArgumentException("Trace must use a sleigh-based language");
		}
		return evaluateWithState(
			SleighProgramCompiler.compileExpression((SleighLanguage) language, expr),
			trace, snap, thread, frame);
	}
}
