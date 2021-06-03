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
package ghidra.app.plugin.core.debug.utils;

import ghidra.async.AsyncDebouncer;
import ghidra.async.AsyncTimer;
import ghidra.framework.model.UndoableDomainObject;
import ghidra.util.Msg;

public class DefaultTransactionCoalescer<T extends UndoableDomainObject, U extends AutoCloseable>
		implements TransactionCoalescer {

	protected class Coalescer {
		private final AsyncDebouncer<Void> debouncer =
			new AsyncDebouncer<>(AsyncTimer.DEFAULT_TIMER, delayMs);
		private final U tid;

		private volatile int activeCount = 0;

		public Coalescer(String description) {
			this.tid = factory.apply(obj, description);

			debouncer.addListener(this::settled);
		}

		private void enter() {
			++activeCount;
		}

		private void exit() {
			if (--activeCount == 0) {
				debouncer.contact(null);
			}
		}

		private void settled(Void __) {
			synchronized (lock) {
				if (activeCount == 0) {
					try {
						tid.close();
					}
					catch (Exception e) {
						Msg.error(this, "Could not close transaction: ", e);
					}
					tx = null;
				}
			}
		}
	}

	public class DefaultCoalescedTx implements CoalescedTx {
		protected DefaultCoalescedTx(String description) {
			synchronized (lock) {
				if (tx == null) {
					tx = new Coalescer(description);
				}
				tx.enter();
			}
		}

		@Override
		public void close() {
			synchronized (lock) {
				tx.exit();
			}
		}
	}

	protected final Object lock = new Object();
	protected final T obj;
	protected final TxFactory<? super T, U> factory;
	protected final int delayMs;

	protected Coalescer tx;

	public DefaultTransactionCoalescer(T obj, TxFactory<? super T, U> factory, int delayMs) {
		this.obj = obj;
		this.factory = factory;
		this.delayMs = delayMs;
	}

	@Override
	public DefaultCoalescedTx start(String description) {
		return new DefaultCoalescedTx(description);
	}
}
