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

import java.util.Deque;
import java.util.LinkedList;

import ghidra.async.AsyncDebouncer;
import ghidra.async.AsyncTimer;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.database.UndoableTransaction;

public class TransactionCoalescer {
	protected final Program program;
	protected final AsyncDebouncer<Void> debouncer;

	protected final Deque<Runnable> coalesced = new LinkedList<>();

	public TransactionCoalescer(Program program, int delayWindow) {
		this.program = program;
		this.debouncer = new AsyncDebouncer<>(AsyncTimer.DEFAULT_TIMER, delayWindow);

		this.debouncer.addListener(v -> processCoalesced());
	}

	protected void processCoalesced() {
		try (UndoableTransaction tid = UndoableTransaction.start(program, "Coalesced", false)) {
			while (true) {
				Runnable next;
				synchronized (coalesced) {
					next = coalesced.poll();
				}
				if (next == null) {
					break;
				}
				next.run();
			}
			tid.commit();
		}
		catch (Exception e) {
			Msg.error(this, "Cancelled coalesced transaction due to exception", e);
		}
		// TODO: Is this really a good place for this?
		program.clearUndo();
	}

	public synchronized void submit(Runnable runnable) {
		coalesced.offer(runnable);
		debouncer.contact(null);
	}
}
