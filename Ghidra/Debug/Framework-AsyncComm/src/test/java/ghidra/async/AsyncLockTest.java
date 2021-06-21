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
package ghidra.async;

import static ghidra.async.AsyncUtils.sequence;
import static org.junit.Assert.assertEquals;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.junit.Ignore;
import org.junit.Test;

import ghidra.util.Msg;

public class AsyncLockTest {

	private AsyncLock lock; // Placeholder for example

	private CompletableFuture<Void> doCriticalStuff() {
		// Placeholder for example
		return AsyncUtils.NIL;
	}

	private CompletableFuture<Void> doMoreCriticalStuff() {
		// Placeholder for example
		return AsyncUtils.NIL;
	}

	public CompletableFuture<Integer> fetchValue() {
		// Placeholder for example
		return CompletableFuture.completedFuture(3);
	}

	public CompletableFuture<String> convertValue(int val) {
		return CompletableFuture.completedFuture(Integer.toString(val));
	}

	public CompletableFuture<Void> exampleSeq() {
		return sequence(TypeSpec.VOID).then((seq) -> {
			fetchValue().handle(seq::next);
		}, TypeSpec.INT).then((val, seq) -> {
			convertValue(val + 10).handle(seq::next);
		}, TypeSpec.STRING).then((str, seq) -> {
			System.out.println(str);
			seq.exit();
		}).finish();
	}

	public CompletableFuture<Void> exampleLock1() {
		AtomicReference<AsyncLock.Hold> hold = new AtomicReference<>();
		return sequence(TypeSpec.VOID).then((seq) -> {
			lock.acquire(null).handle(seq::next);
		}, hold).then((seq) -> {
			doCriticalStuff().handle(seq::next);
		}).then((seq) -> {
			doMoreCriticalStuff().handle(seq::next);
		}).then((seq) -> {
			hold.get().release();
			seq.exit();
		}).finish().exceptionally((exc) -> {
			hold.get().release();
			return ExceptionUtils.rethrow(exc);
		});
	}

	public CompletableFuture<Void> exampleLock2() {
		return lock.with(TypeSpec.VOID, null).then((hold, seq) -> {
			doCriticalStuff().handle(seq::next);
		}).then((seq) -> {
			doMoreCriticalStuff().handle(seq::next);
		}).finish();
	}

	@Test
	public void testReentry() {
		// This is very contrived. A real use would pass ownership to some method which cannot
		// assume that it already holds the lock
		Deque<CompletableFuture<Void>> queue = new LinkedList<>();
		AsyncLock l = new AsyncLock();
		AtomicReference<AsyncLock.Hold> hold = new AtomicReference<>();
		AtomicReference<AsyncLock.Hold> hold2 = new AtomicReference<>();
		List<Integer> result = new ArrayList<>();

		l.with(TypeSpec.VOID, null, hold).then((seq) -> {
			result.add(1);
			CompletableFuture<Void> future = new CompletableFuture<>();
			queue.add(future);
			future.handle(seq::next);
		}).then((seq) -> {
			l.with(TypeSpec.VOID, hold.get(), hold2).then((seq2) -> {
				result.add(2);
				CompletableFuture<Void> future = new CompletableFuture<>();
				queue.add(future);
				future.handle(seq2::next);
			}).finish().handle(seq::next);
		}).then((seq) -> {
			result.add(3);
			seq.exit();
		});

		CompletableFuture<Void> future;
		while (null != (future = queue.poll())) {
			future.complete(null);
		}

		List<Integer> exp = Arrays.asList(new Integer[] { 1, 2, 3 });
		assertEquals(exp, result);
	}

	@Test
	@Ignore("TODO") // Not sure why this fails under Gradle but not my IDE
	public void testTwoSequencesWithLockAtomic() {
		Deque<CompletableFuture<Void>> queue = new LinkedList<>();
		AsyncLock l = new AsyncLock();
		List<Integer> result = new ArrayList<>();

		l.with(TypeSpec.VOID, null).then((hold, seq) -> {
			result.add(1);
			CompletableFuture<Void> future = new CompletableFuture<>();
			queue.add(future);
			future.handle(seq::next);
		}).then((seq) -> {
			result.add(2);
			CompletableFuture<Void> future = new CompletableFuture<>();
			queue.add(future);
			future.handle(seq::next);
		}).then((seq) -> {
			result.add(3);
			seq.exit();
		});
		l.with(TypeSpec.VOID, null).then((hold, seq) -> {
			result.add(4);
			CompletableFuture<Void> future = new CompletableFuture<>();
			queue.add(future);
			future.handle(seq::next);
		}).then((seq) -> {
			result.add(5);
			CompletableFuture<Void> future = new CompletableFuture<>();
			queue.add(future);
			future.handle(seq::next);
		}).then((seq) -> {
			result.add(6);
			seq.exit();
		});

		CompletableFuture<Void> future;
		while (null != (future = queue.poll())) {
			future.complete(null);
		}

		List<Integer> exp = Arrays.asList(new Integer[] { 1, 2, 3, 4, 5, 6 });
		assertEquals(exp, result);
	}

	@Test
	@Ignore("TODO") // Not sure why this fails under Gradle but not my IDE
	public void testTwoSequencesWithReentry() {
		// This is very contrived. A real use would pass ownership to some method which cannot
		// assume that it already owns the lock
		Deque<CompletableFuture<Void>> queue = new LinkedList<>();
		AsyncLock l = new AsyncLock();
		AtomicReference<AsyncLock.Hold> hold = new AtomicReference<>();
		AtomicReference<AsyncLock.Hold> hold2 = new AtomicReference<>();
		List<Integer> result = new ArrayList<>();

		l.with(TypeSpec.VOID, null, hold).then((seq) -> {
			result.add(1);
			CompletableFuture<Void> future = new CompletableFuture<>();
			queue.add(future);
			future.handle(seq::next);
		}).then((seq) -> {
			l.with(TypeSpec.VOID, hold.get(), hold2).then((seq2) -> {
				result.add(2);
				CompletableFuture<Void> future = new CompletableFuture<>();
				queue.add(future);
				future.handle(seq2::next);
			}).finish().handle(seq::next);
		}).then((seq) -> {
			result.add(3);
			seq.exit();
		});
		l.with(TypeSpec.VOID, null, hold).then((seq) -> {
			result.add(4);
			CompletableFuture<Void> future = new CompletableFuture<>();
			queue.add(future);
			future.handle(seq::next);
		}).then((seq) -> {
			l.with(TypeSpec.VOID, hold.get(), hold2).then((seq2) -> {
				result.add(5);
				CompletableFuture<Void> future = new CompletableFuture<>();
				queue.add(future);
				future.handle(seq2::next);
			}).finish().handle(seq::next);
		}).then((seq) -> {
			result.add(6);
			seq.exit();
		});

		CompletableFuture<Void> future;
		while (null != (future = queue.poll())) {
			future.complete(null);
		}

		List<Integer> exp = Arrays.asList(new Integer[] { 1, 2, 3, 4, 5, 6 });
		assertEquals(exp, result);
	}

	@Test(expected = IllegalStateException.class)
	public void testInvalidHandle() throws Throwable {
		Deque<CompletableFuture<Void>> queue = new LinkedList<>();
		AsyncLock l = new AsyncLock();
		AtomicReference<AsyncLock.Hold> hold = new AtomicReference<>();

		l.with(TypeSpec.VOID, null, hold).then((seq) -> {
			CompletableFuture<Void> future = new CompletableFuture<>();
			queue.add(future);
			/*
			 * NOTE: Using seq::next here fails to release the lock, because #asCompletableFuture()
			 * must be called on the sequence to install the automatic call to ::exit.
			 */
			future.handle(seq::exit);
		});

		// Finish the "critical section"
		queue.poll().complete(null);

		try {
			l.with(TypeSpec.VOID, hold.get()).then((drop, seq) -> {
				seq.exit();
			}).finish().getNow(null);
		}
		catch (CompletionException e) {
			throw e.getCause();
		}
	}

	@Test(expected = IllegalStateException.class)
	public void testForgottenHandle() throws Throwable {
		Deque<CompletableFuture<Void>> queue = new LinkedList<>();
		AsyncLock l = new AsyncLock();
		AtomicReference<AsyncLock.Hold> hold = new AtomicReference<>();
		// We have to contrive the forgotten lock, and control garbage collection
		// It shouldn't matter when gc happens, but for the sake of testing, we want it soon

		sequence(TypeSpec.VOID).then((seq) -> {
			l.acquire(null).handle(seq::next);
		}, hold).then((seq) -> {
			CompletableFuture<Void> future = new CompletableFuture<>();
			queue.add(future);
			future.handle(seq::exit);
		});

		// Finish the "critical section"
		queue.poll().complete(null);
		Msg.info(this, "The forgotten lock message is expected");
		// Forget the lock, and wait for it to die
		hold.set(null);
		while (!l.dead) {
			System.gc();
			Thread.sleep(10);
		}

		try {
			l.acquire(null).getNow(null);
		}
		catch (CompletionException e) {
			throw e.getCause();
		}
	}

	@Test
	public void testThrash() throws Exception {
		AsyncLock l = new AsyncLock("testThrash Lock");

		var noSync = new Object() {
			int total = 0;
		};

		AsyncFence fence = new AsyncFence();
		for (int i = 0; i < 10000; i++) {
			final int _i = i;
			fence.include(l.with(TypeSpec.VOID, null).then((hold, seq) -> {
				CompletableFuture.runAsync(() -> {
					Msg.info(this, "i: " + _i);
					Msg.info(this, "Depth: " + new Throwable().getStackTrace().length);
					//assert noSync.total == 0;
					noSync.total++;
				}).handle(seq::next);
			}).then(seq -> {
				CompletableFuture.runAsync(() -> {
					noSync.total--;
				}).handle(seq::next);
			}).finish());
		}

		fence.ready().get(5000000, TimeUnit.MILLISECONDS);
		assert noSync.total == 0;
	}
}
