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
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.MemBuffer;

public class AsyncWrappedPcodeExecutorStatePiece<A, T>
		implements PcodeExecutorStatePiece<CompletableFuture<A>, CompletableFuture<T>> {
	protected final PcodeExecutorStatePiece<A, T> state;
	private CompletableFuture<?> lastWrite = AsyncUtils.NIL;

	public AsyncWrappedPcodeExecutorStatePiece(PcodeExecutorStatePiece<A, T> state) {
		this.state = state;
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
			int size, boolean truncateAddressableUnit, CompletableFuture<T> val) {
		return offset.thenCompose(off -> val.thenAccept(v -> {
			state.setVar(space, off, size, truncateAddressableUnit, v);
		}));
	}

	@Override
	public void setVar(AddressSpace space, CompletableFuture<A> offset, int size,
			boolean truncateAddressableUnit, CompletableFuture<T> val) {
		nextWrite(() -> doSetVar(space, offset, size, truncateAddressableUnit, val));
	}

	protected CompletableFuture<T> doGetVar(AddressSpace space, CompletableFuture<A> offset,
			int size, boolean truncateAddressableUnit) {
		return offset.thenApply(off -> {
			return state.getVar(space, off, size, truncateAddressableUnit);
		});
	}

	@Override
	public CompletableFuture<T> getVar(AddressSpace space, CompletableFuture<A> offset, int size,
			boolean truncateAddressableUnit) {
		return nextRead(() -> doGetVar(space, offset, size, truncateAddressableUnit));
	}

	@Override
	public CompletableFuture<A> longToOffset(AddressSpace space, long l) {
		return CompletableFuture.completedFuture(state.longToOffset(space, l));
	}

	@Override
	public MemBuffer getConcreteBuffer(Address address) {
		if (!isWriteDone()) {
			throw new AssertionError("An async write is still pending");
		}
		return state.getConcreteBuffer(address);
	}
}
