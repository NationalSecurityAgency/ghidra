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
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.trace.model.Trace;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.thread.TraceThread;

/**
 * Various utilities for using Sleigh with traces
 */
public enum TraceSleighUtils {
	;

	/**
	 * Build a p-code executor that operates directly on bytes of the given trace
	 * 
	 * <p>
	 * This execute is most suitable for evaluating Sleigh expression on a given trace snapshot, and
	 * for manipulating or initializing variables using Sleigh code. It is generally not suitable
	 * for use in an emulator. For that, consider {@link BytesTracePcodeEmulator}.
	 * 
	 * @param platform the platform
	 * @param snap the snap
	 * @param thread the thread, required if register space is used
	 * @param frame the frame, for when register space is used
	 * @return the executor
	 */
	public static PcodeExecutor<byte[]> buildByteExecutor(TracePlatform platform, long snap,
			TraceThread thread, int frame) {
		DirectBytesTracePcodeExecutorState state =
			new DirectBytesTracePcodeExecutorState(platform, snap, thread, frame);
		Language language = platform.getLanguage();
		if (!(language instanceof SleighLanguage)) {
			throw new IllegalArgumentException("TracePlatform must use a SLEIGH language");
		}
		return new PcodeExecutor<>((SleighLanguage) language,
			BytesPcodeArithmetic.forLanguage(language), state, Reason.INSPECT);
	}

	/**
	 * @see #buildByteExecutor(TracePlatform, long, TraceThread, int)
	 * @param trace the trace whose host platform to use
	 * @param snap the snap
	 * @param thread the thread, required if register space is used
	 * @param frame the frame, for when register space is used
	 * @return the executor
	 */
	public static PcodeExecutor<byte[]> buildByteExecutor(Trace trace, long snap,
			TraceThread thread, int frame) {
		return buildByteExecutor(trace.getPlatformManager().getHostPlatform(), snap, thread, frame);
	}

	/**
	 * Build a p-code executor that operates directly on bytes and memory state of the given trace
	 * 
	 * <p>
	 * This executor is most suitable for evaluating Sleigh expressions on a given trace snapshot,
	 * when the client would also like to know if all variables involved are
	 * {@link TraceMemoryState#KNOWN}.
	 * 
	 * @param platform the platform
	 * @param snap the snap
	 * @param thread the thread, required if register space is used
	 * @param frame the frame, for when register space is used
	 * @return the executor
	 */
	public static PcodeExecutor<Pair<byte[], TraceMemoryState>> buildByteWithStateExecutor(
			TracePlatform platform, long snap, TraceThread thread, int frame) {
		DirectBytesTracePcodeExecutorState state =
			new DirectBytesTracePcodeExecutorState(platform, snap, thread, frame);
		PcodeExecutorState<Pair<byte[], TraceMemoryState>> paired = state.withMemoryState();
		Language language = platform.getLanguage();
		if (!(language instanceof SleighLanguage)) {
			throw new IllegalArgumentException("TracePlatform must use a SLEIGH language");
		}
		return new PcodeExecutor<>((SleighLanguage) language, new PairedPcodeArithmetic<>(
			BytesPcodeArithmetic.forLanguage(language), TraceMemoryStatePcodeArithmetic.INSTANCE),
			paired, Reason.INSPECT);
	}

	/**
	 * @see #buildByteWithStateExecutor(TracePlatform, long, TraceThread, int)
	 * @param trace the trace whose host platform to use
	 * @param snap the snap
	 * @param thread the thread, required if register space is used
	 * @param frame the frame, for when register space is used
	 * @return the executor
	 */
	public static PcodeExecutor<Pair<byte[], TraceMemoryState>> buildByteWithStateExecutor(
			Trace trace, long snap, TraceThread thread, int frame) {
		return buildByteWithStateExecutor(trace.getPlatformManager().getHostPlatform(), snap,
			thread, frame);
	}

	/**
	 * Evaluate a compiled p-code expression on the given trace
	 * 
	 * @param expr the expression
	 * @param trace the trace
	 * @param snap the snap
	 * @param thread the thread, required if register space is used
	 * @param frame the frame, for when register space is used
	 * @return the value of the expression as a byte array
	 */
	public static byte[] evaluateBytes(PcodeExpression expr, Trace trace, long snap,
			TraceThread thread, int frame) {
		SleighLanguage language = expr.getLanguage();
		if (trace.getBaseLanguage() != language) {
			throw new IllegalArgumentException(
				"This expression can only be evaulated on traces with language " + language);
		}
		PcodeExecutor<byte[]> executor = buildByteExecutor(trace, snap, thread, frame);
		return expr.evaluate(executor);
	}

	/**
	 * Evaluate a compiled p-code expression on the given trace
	 * 
	 * @param expr the expression
	 * @param trace the trace
	 * @param snap the snap
	 * @param thread the thread, required if register space is used
	 * @param frame the frame, for when register space is used
	 * @return the value of the expression as a big integer
	 */
	public static BigInteger evaluate(PcodeExpression expr, Trace trace, long snap,
			TraceThread thread, int frame) {
		byte[] bytes = evaluateBytes(expr, trace, snap, thread, frame);
		return Utils.bytesToBigInteger(bytes, bytes.length, expr.getLanguage().isBigEndian(),
			false);
	}

	/**
	 * Evaluate a compiled p-code expression on the given trace
	 * 
	 * @param expr the expression
	 * @param trace the trace
	 * @param snap the snap
	 * @param thread the thread, required if register space is used
	 * @param frame the frame, for when register space is used
	 * @return the value and state of the expression
	 */
	public static Pair<byte[], TraceMemoryState> evaluateBytesWithState(PcodeExpression expr,
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

	/**
	 * Evaluate a compiled p-code expression on the given trace
	 * 
	 * @param expr the expression
	 * @param trace the trace
	 * @param snap the snap
	 * @param thread the thread, required if register space is used
	 * @param frame the frame, for when register space is used
	 * @return the value and state of the expression
	 */
	public static Pair<BigInteger, TraceMemoryState> evaluateWithState(PcodeExpression expr,
			Trace trace, long snap, TraceThread thread, int frame) {
		Pair<byte[], TraceMemoryState> bytesPair =
			evaluateBytesWithState(expr, trace, snap, thread, frame);
		byte[] bytes = bytesPair.getLeft();
		return new ImmutablePair<>(
			Utils.bytesToBigInteger(bytes, bytes.length, expr.getLanguage().isBigEndian(), false),
			bytesPair.getRight());
	}

	/**
	 * Evaluate a Sleigh expression on the given trace
	 * 
	 * @param expr the expression
	 * @param trace the trace
	 * @param snap the snap
	 * @param thread the thread, required if register space is used
	 * @param frame the frame, for when register space is used
	 * @return the value of the expression as a byte array
	 */
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

	/**
	 * Evaluate a Sleigh expression on the given trace
	 * 
	 * @param expr the expression
	 * @param trace the trace
	 * @param snap the snap
	 * @param thread the thread, required if register space is used
	 * @param frame the frame, for when register space is used
	 * @return the value of the expression as a big integer
	 */
	public static BigInteger evaluate(String expr, Trace trace, long snap, TraceThread thread,
			int frame) {
		Language language = trace.getBaseLanguage();
		if (!(language instanceof SleighLanguage)) {
			throw new IllegalArgumentException("Trace must use a sleigh-based language");
		}
		return evaluate(SleighProgramCompiler.compileExpression((SleighLanguage) language, expr),
			trace, snap, thread, frame);
	}

	/**
	 * Evaluate a Sleigh expression on the given trace
	 * 
	 * @param expr the expression
	 * @param trace the trace
	 * @param snap the snap
	 * @param thread the thread, required if register space is used
	 * @param frame the frame, for when register space is used
	 * @return the value and state of the expression
	 */
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

	/**
	 * Evaluate a Sleigh expression on the given trace
	 * 
	 * @param expr the expression
	 * @param trace the trace
	 * @param snap the snap
	 * @param thread the thread, required if register space is used
	 * @param frame the frame, for when register space is used
	 * @return the value and state of the expression
	 */
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

	/**
	 * Generate the expression for retrieving a memory range
	 * 
	 * <p>
	 * In general, it does not make sense to use this directly with the above evaluation methods.
	 * More likely, this is used in the UI to aid the user in generating an expression. From the
	 * API, it's much easier to access the memory state directly.
	 * 
	 * @param language the language
	 * @param range the range
	 * @return the expression
	 */
	public static String generateExpressionForRange(Language language, AddressRange range) {
		AddressSpace space = range.getAddressSpace();
		long length = range.getLength();
		long offset = range.getMinAddress().getOffset();
		int ptrSize = space.getPointerSize();
		if (language != null && language.getDefaultSpace() == space) {
			return String.format("*:%d 0x%08x:%d", length, offset, ptrSize);
		}
		return String.format("*[%s]:%d 0x%08x:%d", space.getName(), length, offset, ptrSize);
	}
}
