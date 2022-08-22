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

import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

import ghidra.async.AsyncUtils;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.MemBuffer;

/**
 * An executor state piece which can operate on futures of a wrapped type
 *
 * @see AsyncPcodeExecutor for comment regarding potential deprecation or immediate removal
 * @param <T> the type of values wrapped
 */
public class AsyncWrappedPcodeExecutorStatePiece<A, T>
		implements PcodeExecutorStatePiece<CompletableFuture<A>, CompletableFuture<T>> {
	protected final PcodeExecutorStatePiece<A, T> state;
	protected final AsyncWrappedPcodeArithmetic<A> addressArithmetic;
	protected final AsyncWrappedPcodeArithmetic<T> arithmetic;
	private CompletableFuture<?> lastWrite = AsyncUtils.NIL;

	public AsyncWrappedPcodeExecutorStatePiece(PcodeExecutorStatePiece<A, T> state) {
		this.state = state;
		this.addressArithmetic = new AsyncWrappedPcodeArithmetic<>(state.getAddressArithmetic());
		this.arithmetic = new AsyncWrappedPcodeArithmetic<>(state.getArithmetic());
	}

	@Override
	public AsyncWrappedPcodeArithmetic<A> getAddressArithmetic() {
		return addressArithmetic;
	}

	@Override
	public AsyncWrappedPcodeArithmetic<T> getArithmetic() {
		return arithmetic;
	}

	protected boolean isWriteDone() {
		return lastWrite.isDone();
	}

	protected <U> CompletableFuture<U> nextRead(Supplier<CompletableFuture<U>> next) {
		return lastWrite.thenCompose(__ -> next.get()).exceptionally(ex -> null);
	}

	protected <U> void nextWrite(Supplier<CompletableFuture<U>> next) {
		lastWrite = nextRead(next);
	}

	protected CompletableFuture<?> doSetVar(AddressSpace space, CompletableFuture<A> offset,
			int size, boolean quantize, CompletableFuture<T> val) {
		return offset.thenCompose(off -> val.thenAccept(v -> {
			state.setVar(space, off, size, quantize, v);
		}));
	}

	@Override
	public void setVar(AddressSpace space, CompletableFuture<A> offset, int size,
			boolean quantize, CompletableFuture<T> val) {
		nextWrite(() -> doSetVar(space, offset, size, quantize, val));
	}

	protected CompletableFuture<T> doGetVar(AddressSpace space, CompletableFuture<A> offset,
			int size, boolean quantize) {
		return offset.thenApply(off -> {
			return state.getVar(space, off, size, quantize);
		});
	}

	@Override
	public CompletableFuture<T> getVar(AddressSpace space, CompletableFuture<A> offset, int size,
			boolean quantize) {
		return nextRead(() -> doGetVar(space, offset, size, quantize));
	}

	@Override
	public MemBuffer getConcreteBuffer(Address address, Purpose purpose) {
		if (!isWriteDone()) {
			throw new AssertionError("An async write is still pending");
		}
		return state.getConcreteBuffer(address, purpose);
	}
}
