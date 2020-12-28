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

import java.lang.ref.Cleaner.Cleanable;
import java.lang.ref.WeakReference;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.Lock;

import ghidra.async.seq.AsyncSequenceWithTemp;
import ghidra.async.seq.AsyncSequenceWithoutTemp;
import ghidra.util.Msg;

/**
 * An optionally-reentrant lock for managing a contentious resource
 * 
 * <p>
 * Typically, a resource has a queue of actions that it executes in order, or it may only permit a
 * single pending action at any given time. If a task composed of many actions needs to ensure no
 * other actions are queued in between, it must use a lock. This is analogous to thread
 * synchronization. This can also be described as a queue to enter other queues.
 * 
 * <p>
 * Example:
 * 
 * <pre>
 * public CompletableFuture<Void> exampleLock1() {
 * 	AtomicReference<AsyncLock.Hold> hold = new AtomicReference<>();
 * 	return seq(TypeSpec.VOID).then((seq) -> {
 * 		lock.acquire(null).handle(seq::next);
 * 	}, hold).then((seq) -> {
 * 		doCriticalStuff().handle(seq::next);
 * 	}).then((seq) -> {
 * 		doMoreCriticalStuff().handle(seq::next);
 * 	}).then((seq) -> {
 * 		hold.release();
 * 		seq.exit();
 * 	}).asCompletableFuture().exceptionally((exc) -> {
 * 		hold.release();
 * 		return ExceptionUtils.rethrow(exc);
 * 	});
 * }
 * </pre>
 * 
 * <p>
 * Or more succinctly:
 * 
 * <pre>
 * public CompletableFuture<Void> exampleLock2() {
 * 	return lock.with(TypeSpec.VOID, null).then((hold, seq) -> {
 * 		doCriticalStuff().handle(seq::next);
 * 	}).then((seq) -> {
 * 		doMoreCriticalStuff().handle(seq::next);
 * 	}).asCompletableFuture();
 * }
 * </pre>
 * 
 * <p>
 * Re-entry is supported via a {@link Hold}. A method that offers re-enter into a critical section
 * must accept a {@link Hold} parameter. Generally, the caller indicates the callee should reenter
 * by passing the current hold. It then forwards it to the lock, via {@link #acquire(Hold)} or
 * {@link #with(TypeSpec, Hold)}. The hold must be a reference to the current hold or null. A hold
 * from another lock cannot be used for re-entry. If it is null, normal behavior is applied and the
 * queue is served in FIFO order. If it is a reference to the current hold, the callback is executed
 * immediately. Reentrant holds must be released in the reverse order of acquisition.
 * 
 * <pre>
 * public CompletableFuture<Void> canReenter(Hold reenter) {
 * 	return lock.with(TypeSpec.VOID, reenter).then((hold, seq) -> {
 * 		doCriticalStuff();
 * 	}).asCompletableFuture();
 * }
 * 
 * public CompletableFuture<Void> exampleLock3() {
 * 	return lock.with(TypeSpec.VOID, null).then((hold, seq) -> {
 * 		canReenter(hold).handle(seq::next);
 * 	}).then((seq) -> {
 * 		doMoreCriticalStuff().handle(seq::next);
 * 	}).asCompletableFuture();
 * }
 * </pre>
 * 
 * <p>
 * The implementation is based on a queue a queue of futures. The {@link #acquire(Hold)} task
 * completes when the lock is available or if re-entry is possible. {@link Hold#release()} is not a
 * task, but it must be called to ensure the next handler is invoked. If a hold is forgotten, e.g.,
 * a sequence fails to release it, deadlock will likely occur. In some circumstances, deadlock is
 * detected, causing all queued actions (current and future) to complete exceptionally with an
 * {@link IllegalStateException}. Deadlock detection is a debugging feature. A programmer cannot
 * rely on it for error recovery. If the exception is thrown, it indicates a serious flaw in the
 * program which cannot be corrected at runtime.
 * 
 * <p>
 * The above examples demonstrate two critical actions, because in general, a single action is
 * atomic. This lock <em>does not</em> protect against the usual multi-threaded hazards. Because any
 * queue may be served by a multi-threaded executor, shared resources must be protected using
 * standard synchronization primitives, e.g., the {@code synchronized} keyword. Resources whose
 * methods provide futures are better protected using this lock, because a standard {@link Lock}
 * will block the calling thread -- perhaps stalling a queue's executor -- whereas this lock permits
 * the thread to execute other actions.
 * 
 * @note This implementation offers little protection against double locking, or gratuitous
 *       releasing.
 * @note As an asynchronous task, {@link #acquire()} returns immediately, but the future does not
 *       complete until the lock is acquired.
 */
public class AsyncLock {
	private class HoldState implements Runnable {
		boolean released = false;

		@Override
		public void run() {
			if (!released) {
				Msg.error(this, "Some poor soul forgot to release a lock. Now, it's dead!");
				dead = true;
				List<CompletableFuture<?>> copy;
				synchronized (AsyncLock.this) {
					copy = List.copyOf(queue);
					queue.clear();
				}
				for (CompletableFuture<?> future : copy) {
					future.completeExceptionally(new IllegalStateException("This lock is dead! " +
						"I.e., an ownership token became phantom reachable without first being " +
						"released"));
				}
			}
		}
	}

	protected final Deque<CompletableFuture<Hold>> queue = new LinkedList<>();
	protected WeakReference<Hold> curHold;
	protected int reentries = 0;
	protected Throwable disposalReason;
	protected boolean dead = false;
	protected final String debugName;

	/**
	 * An opaque lock ownership handle
	 */
	public class Hold {
		final HoldState state = new HoldState();
		final Cleanable cleanable;

		private Hold() {
			cleanable = AsyncUtils.CLEANER.register(this, state);
		}

		/**
		 * Release ownership of the associated lock
		 */
		public void release() {
			debug(this + ".release()");
			CompletableFuture<Hold> next;
			Hold oldHold = null;
			synchronized (AsyncLock.this) {
				oldHold = curHold.get();
				if (this != oldHold) {
					Msg.error(this, "Invalid ownership handle: " + oldHold + " != " + this);
					throw new IllegalStateException("Invalid ownership handle");
				}
				if (reentries > 0) {
					debug("    is from reentry");
					reentries--;
					return;
				}
				debug("    is non-reentrant release");
				state.released = true;
				next = queue.poll();
				if (next != null) {
					debug("    has queued waiters");
					Hold newHold = new Hold();
					curHold = new WeakReference<>(newHold);
					debug("    launching next, granting " + newHold);
					// Use completeAsync, since I'm inside synchronized block
					next.completeAsync(() -> newHold);
					return;
				}
				debug("    has no waiters");
				curHold = null;
				return;
			}
		}
	}

	/**
	 * Construct a new lock
	 */
	public AsyncLock() {
		this(null);
	}

	/**
	 * Construct a lock with debug printing
	 * 
	 * <p>
	 * This lock will print calls to {@link #acquire(Hold)} and {@link Hold#release()}. It will also
	 * note when the lock is acquired or re-entered, printing the current hold.
	 * 
	 * @param debugName a name to prefix to debug messages
	 */
	public AsyncLock(String debugName) {
		this.debugName = debugName;
	}

	private void debug(String msg) {
		if (debugName != null) {
			Msg.debug(this, "LOCK: " + debugName + ": " + msg);
		}
	}

	/**
	 * Queue a future on this lock, possibly re-entering
	 * 
	 * <p>
	 * If reentry is {@code null}, then this will acquire the lock without reentry. Otherwise, the
	 * lock checks the provided hold. If it is valid, the lock is immediately acquired via re-entry.
	 * If it is not valid, an exception is thrown.
	 * 
	 * @param reentry a hold to prove current lock ownership for reentry
	 * @return a future that completes when the lock is held
	 * @throws IllegalStateException if the given reentry hold is not the current hold on this lock
	 */
	public CompletableFuture<Hold> acquire(Hold reentry) {
		debug(".acquire(" + reentry + ")");
		Hold strongHold = null;
		synchronized (this) {
			if (disposalReason != null) {
				return CompletableFuture.failedFuture(disposalReason);
			}
			if (dead) {
				throw new IllegalStateException("This lock is dead! " +
					"I.e., an ownership token was finalized without first being released");
			}
			if (reentry == null && curHold != null) {
				debug("    is held: queuing");
				CompletableFuture<Hold> future = new CompletableFuture<>();
				queue.add(future);
				return future;
			}
			if (reentry == null && curHold == null) {
				strongHold = new Hold();
				debug("    is available: granting " + strongHold);
				curHold = new WeakReference<>(strongHold);
				return CompletableFuture.completedFuture(strongHold);
			}
			if (reentry.state.released) {
				throw new IllegalStateException("Reentrant hold is released");
			}
			if (reentry == curHold.get()) {
				debug("    is held by requester: reentering");
				reentries++;
				return CompletableFuture.completedFuture(reentry);
			}
			// TODO: This might actually be an internal error.
			// I can't think of a situation where this could occur by API misuse.
			throw new IllegalStateException("Reentrant hold is not the current hold");
		}
	}

	/**
	 * Queue a sequence of actions on this lock
	 * 
	 * The lock will be acquired before executing the first action of the sequence, and the hold
	 * will be automatically released upon completion, whether normal or exceptional. The first
	 * action receives a reference to the hold, which may be used to re-enter the lock.
	 * 
	 * If the sequence stalls, i.e., an action never completes, it will cause deadlock.
	 * 
	 * @param type the type "returned" by the sequence
	 * @param hold an optional handle to prove current ownership for re-entry
	 * @return a sequence of actions wrapped by lock acquisition and release
	 */
	public <R> AsyncSequenceWithTemp<R, Hold> with(TypeSpec<R> type, Hold hold) {
		AtomicReference<Hold> handle = new AtomicReference<>();
		return with(type, hold, handle).then((seq) -> {
			seq.next(handle.get(), null);
		}, TypeSpec.cls(Hold.class));
	}

	/**
	 * Queue a sequence of actions on this lock
	 * 
	 * Identical to {@link #with(TypeSpec, Hold)} except that the acquired hold is stored into an
	 * atomic reference rather than passed to the first action.
	 * 
	 * @param type the type "returned" by the sequence
	 * @param hold an optional hold to prove current ownership for re-entry
	 * @param handle an atomic reference to store the hold
	 * @see #with(TypeSpec, Hold)
	 * @return a sequence of actions wrapped by lock acquisition and release
	 */
	public <R> AsyncSequenceWithoutTemp<R> with(TypeSpec<R> type, Hold hold,
			AtomicReference<Hold> handle) {
		return sequence(type).then((seq) -> {
			acquire(hold).handle(seq::next);
		}, handle).onExit((result, exc) -> {
			handle.get().release();
		});
	}

	/**
	 * Destroy this lock, causing all pending actions to complete exceptionally
	 */
	public void dispose(Throwable reason) {
		List<CompletableFuture<?>> copy;
		synchronized (this) {
			disposalReason = reason;
			copy = List.copyOf(queue);
			queue.clear();
		}
		for (CompletableFuture<?> future : copy) {
			future.completeExceptionally(reason);
		}
	}
}
