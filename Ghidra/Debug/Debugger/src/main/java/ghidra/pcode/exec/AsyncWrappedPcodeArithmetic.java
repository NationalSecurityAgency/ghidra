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

import java.util.Objects;
import java.util.concurrent.CompletableFuture;

import ghidra.program.model.lang.Endian;
import ghidra.program.model.lang.Language;

/**
 * An arithmetic which can operate on futures of a wrapped type
 *
 * @see AsyncPcodeExecutor for comment regarding potential deprecation or immediate removal
 * @param <T> the type of values wrapped
 */
public class AsyncWrappedPcodeArithmetic<T> implements PcodeArithmetic<CompletableFuture<T>> {
	public static final AsyncWrappedPcodeArithmetic<byte[]> BYTES_BE =
		new AsyncWrappedPcodeArithmetic<>(BytesPcodeArithmetic.BIG_ENDIAN);
	public static final AsyncWrappedPcodeArithmetic<byte[]> BYTES_LE =
		new AsyncWrappedPcodeArithmetic<>(BytesPcodeArithmetic.LITTLE_ENDIAN);

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
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (this.getClass() != obj.getClass()) {
			return false;
		}
		AsyncWrappedPcodeArithmetic<?> that = (AsyncWrappedPcodeArithmetic<?>) obj;
		return Objects.equals(this.arithmetic, that.arithmetic);
	}

	@Override
	public Endian getEndian() {
		return arithmetic.getEndian();
	}

	@Override
	public CompletableFuture<T> unaryOp(int opcode, int sizeout, int sizein1,
			CompletableFuture<T> in1) {
		return in1.thenApply(t1 -> arithmetic.unaryOp(opcode, sizeout, sizein1, t1));
	}

	@Override
	public CompletableFuture<T> binaryOp(int opcode, int sizeout, int sizein1,
			CompletableFuture<T> in1, int sizein2, CompletableFuture<T> in2) {
		return in1.thenCombine(in2,
			(t1, t2) -> arithmetic.binaryOp(opcode, sizeout, sizein1, t1, sizein2, t2));
	}

	@Override
	public CompletableFuture<T> modBeforeStore(int sizeout, int sizeinAddress,
			CompletableFuture<T> inAddress, int sizeinValue, CompletableFuture<T> inValue) {
		return inValue;
	}

	@Override
	public CompletableFuture<T> modAfterLoad(int sizeout, int sizeinAddress,
			CompletableFuture<T> inAddress, int sizeinValue, CompletableFuture<T> inValue) {
		return inValue;
	}

	@Override
	public CompletableFuture<T> fromConst(byte[] value) {
		return CompletableFuture.completedFuture(arithmetic.fromConst(value));
	}

	@Override
	public byte[] toConcrete(CompletableFuture<T> value, Purpose purpose) {
		if (!value.isDone()) {
			throw new ConcretionError("You need a better 8-ball", purpose);
		}
		return arithmetic.toConcrete(value.getNow(null), purpose);
	}

	@Override
	public long sizeOf(CompletableFuture<T> value) {
		if (!value.isDone()) {
			// TODO: Make a class which has future and expected size?
			throw new RuntimeException("You need a better 8-ball");
		}
		return arithmetic.sizeOf(value.getNow(null));
	}

	@Override
	public CompletableFuture<T> sizeOfAbstract(CompletableFuture<T> value) {
		return value.thenApply(v -> arithmetic.sizeOfAbstract(v));
	}
}
