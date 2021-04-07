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

import java.util.concurrent.*;
import java.util.function.Function;

import org.apache.commons.lang3.concurrent.BasicThreadFactory;

import ghidra.app.plugin.core.debug.utils.DefaultTransactionCoalescer;
import ghidra.app.plugin.core.debug.utils.TransactionCoalescer;
import ghidra.app.plugin.core.debug.utils.TransactionCoalescer.CoalescedTx;
import ghidra.framework.model.UndoableDomainObject;
import ghidra.util.Msg;

public class PermanentTransactionExecutor {

	private final TransactionCoalescer txc;
	private final Executor executor;
	private final UndoableDomainObject obj;

	public PermanentTransactionExecutor(UndoableDomainObject obj, String name,
			Function<ThreadFactory, Executor> executorFactory, int delayMs) {
		this.obj = obj;
		txc = new DefaultTransactionCoalescer<>(obj, RecorderPermanentTransaction::start, delayMs);
		this.executor = executorFactory.apply(
			new BasicThreadFactory.Builder().namingPattern(name + "-thread-%d").build());
	}

	public void execute(String description, Runnable runnable) {
		CompletableFuture.runAsync(() -> {
			if (obj.isClosed()) {
				return;
			}
			try (CoalescedTx tx = txc.start(description)) {
				runnable.run();
			}
		}, executor).exceptionally(e -> {
			Msg.error(this, "Trouble recording " + description, e);
			return null;
		});
	}
}
