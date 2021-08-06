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
package ghidra.pcode.exec;

import java.math.BigInteger;
import java.util.concurrent.CompletableFuture;

import ghidra.pcode.opbehavior.BinaryOpBehavior;
import ghidra.pcode.opbehavior.UnaryOpBehavior;
import ghidra.program.model.lang.Language;

public class AsyncWrappedPcodeArithmetic<T> implements PcodeArithmetic<CompletableFuture<T>> {
	public static final AsyncWrappedPcodeArithmetic<byte[]> BYTES_BE =
		new AsyncWrappedPcodeArithmetic<>(BytesPcodeArithmetic.BIG_ENDIAN);
	public static final AsyncWrappedPcodeArithmetic<byte[]> BYTES_LE =
		new AsyncWrappedPcodeArithmetic<>(BytesPcodeArithmetic.LITTLE_ENDIAN);
	public static final AsyncWrappedPcodeArithmetic<BigInteger> BIGINT =
		new AsyncWrappedPcodeArithmetic<>(BigIntegerPcodeArithmetic.INSTANCE);

	public static AsyncWrappedPcodeArithmetic<byte[]> forEndian(boolean isBigEndian) {
		return isBigEndian ? BYTES_BE : BYTES_LE;
	}

	public static AsyncWrappedPcodeArithmetic<byte[]> forLanguage(Language language) {
		return forEndian(language.isBigEndian());
	}

	private final PcodeArithmetic<T> arithmetic;

	public AsyncWrappedPcodeArithmetic(PcodeArithmetic<T> arithmetic) {
		this.arithmetic = arithmetic;
	}

	@Override
	public CompletableFuture<T> unaryOp(UnaryOpBehavior op, int sizeout, int sizein1,
			CompletableFuture<T> in1) {
		return in1.thenApply(t1 -> arithmetic.unaryOp(op, sizeout, sizein1, t1));
	}

	@Override
	public CompletableFuture<T> binaryOp(BinaryOpBehavior op, int sizeout, int sizein1,
			CompletableFuture<T> in1, int sizein2, CompletableFuture<T> in2) {
		return in1.thenCombine(in2,
			(t1, t2) -> arithmetic.binaryOp(op, sizeout, sizein1, t1, sizein2, t2));
	}

	@Override
	public CompletableFuture<T> fromConst(long value, int size) {
		return CompletableFuture.completedFuture(arithmetic.fromConst(value, size));
	}

	@Override
	public CompletableFuture<T> fromConst(BigInteger value, int size) {
		return CompletableFuture.completedFuture(arithmetic.fromConst(value, size));
	}

	@Override
	public boolean isTrue(CompletableFuture<T> cond) {
		if (!cond.isDone()) {
			throw new AssertionError("You need a better 8-ball");
		}
		return arithmetic.isTrue(cond.getNow(null));
	}

	@Override
	public BigInteger toConcrete(CompletableFuture<T> cond) {
		if (!cond.isDone()) {
			throw new AssertionError("You need a better 8-ball");
		}
		return arithmetic.toConcrete(cond.getNow(null));
	}
}
