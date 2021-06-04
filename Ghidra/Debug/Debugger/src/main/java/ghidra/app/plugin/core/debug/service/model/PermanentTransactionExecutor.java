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
package ghidra.app.plugin.core.debug.service.model;

import java.util.HashMap;
import java.util.concurrent.*;
import java.util.stream.Stream;

import org.apache.commons.lang3.concurrent.BasicThreadFactory;

import ghidra.app.plugin.core.debug.utils.DefaultTransactionCoalescer;
import ghidra.app.plugin.core.debug.utils.TransactionCoalescer;
import ghidra.app.plugin.core.debug.utils.TransactionCoalescer.CoalescedTx;
import ghidra.framework.model.UndoableDomainObject;
import ghidra.util.Msg;

public class PermanentTransactionExecutor {

	private final TransactionCoalescer txc;
	private final Executor[] threads;
	private final UndoableDomainObject obj;

	public PermanentTransactionExecutor(UndoableDomainObject obj, String name, int threadCount,
			int delayMs) {
		this.obj = obj;
		txc = new DefaultTransactionCoalescer<>(obj, RecorderPermanentTransaction::start, delayMs);
		this.threads = new Executor[threadCount];
		for (int i = 0; i < threadCount; i++) {
			ThreadFactory factory = new BasicThreadFactory.Builder()
					.namingPattern(name + "thread-" + i + "-%d")
					.build();
			threads[i] = Executors.newSingleThreadExecutor(factory);
		}
	}

	/**
	 * This hash is borrowed from {@link HashMap}, except for the power-of-two masking, since I
	 * don't want to force the thread count to be a power of two (though it probably is). In the
	 * grand scheme of things, one division operation is small per transaction.
	 * 
	 * @param sel the basis for selecting a thread
	 * @return the selected executor
	 */
	protected Executor selectThread(Object sel) {
		if (sel == null) {
			return threads[0];
		}
		int h = sel.hashCode();
		return threads[Integer.remainderUnsigned(h ^ (h >>> 16), threads.length)];
	}

	public CompletableFuture<Void> execute(String description, Runnable runnable, Object sel) {
		return CompletableFuture.runAsync(() -> {
			if (obj.isClosed()) {
				return;
			}
			try (CoalescedTx tx = txc.start(description)) {
				runnable.run();
			}
		}, selectThread(sel)).exceptionally(e -> {
			Msg.error(this, "Trouble recording " + description, e);
			return null;
		});
	}

	public CompletableFuture<Void> flush() {
		Runnable nop = () -> {
		};
		return CompletableFuture.allOf(Stream.of(threads)
				.map(t -> CompletableFuture.runAsync(nop, t))
				.toArray(CompletableFuture[]::new));
	}
}
