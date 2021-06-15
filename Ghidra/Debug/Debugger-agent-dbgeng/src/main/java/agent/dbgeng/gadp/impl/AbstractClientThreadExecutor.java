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
package agent.dbgeng.gadp.impl;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

import com.sun.jna.platform.win32.COM.COMException;

import agent.dbgeng.dbgeng.DebugClient;
import agent.dbgeng.dbgeng.DebugClient.DebugStatus;
import agent.dbgeng.dbgeng.DebugControl;
import agent.dbgeng.manager.DbgManager;
import ghidra.util.Msg;

/**
 * A single-threaded executor which creates and exclusively accesses the {@code dbgeng.dll} client.
 * 
 * <p>
 * The executor also has a priority mechanism, so that callbacks may register follow-on handlers
 * which take precedence over other tasks in the queue (which could trigger additional callbacks).
 * This is required since certain operation are not allowed during normal callback processing. For
 * example, changing the current process is typically not allowed, but it is necessary to retrieve a
 * thread's context.
 */
public abstract class AbstractClientThreadExecutor extends AbstractExecutorService {
	private static final int DEFAULT_PRIORITY = 10;

	protected DebugClient client;
	protected boolean shuttingDown = false;
	protected final Queue<Entry> queue = new PriorityQueue<>();
	protected Thread thread = new Thread(this::run, "DebugClient");
	protected final AtomicBoolean waitRegistered = new AtomicBoolean();

	protected abstract void init();

	public static class Entry implements Comparable<Entry> {
		final int priority;
		public final Runnable command;

		public Entry(int priority, Runnable command) {
			this.priority = priority;
			this.command = command;
		}

		@Override
		public int compareTo(Entry that) {
			return Integer.compare(this.priority, that.priority);
		}
	}

	/**
	 * Obtain a reference to the client, only if the calling thread is this executor's thread.
	 * 
	 * @return the client
	 */
	public DebugClient getClient() {
		if (thread != Thread.currentThread()) {
			//TODO: throw new AssertionError("Cannot get client outside owning thread");
		}
		return client;
	}

	/**
	 * Instruct the executor to call {@link DebugClient#dispatchCallbacks()} when it next idles.
	 */
	public void cancelWait() {
		waitRegistered.set(false);
	}

	/**
	 * Instruct the executor to call {@link DebugControl#waitForEvent()} when it next idles.
	 */
	public void registerWait() {
		waitRegistered.set(true);
	}

	private Entry pollQueue() {
		synchronized (queue) {
			return queue.poll();
		}
	}

	private void run() {
		/**
		 * The general idea is to run indefinitely, taking every precaution to protect this thread's
		 * life, since only it can access the client. Granted, if it turns out to be too difficult,
		 * we can always create a new thread and client, using the existing client's reentrant
		 * methods.
		 * 
		 * <p>
		 * As stated in the MSDN, this thread repeatedly calls {@code DispatchEvents} in order to
		 * receive callbacks regarding events caused by other clients. If, however, an wait is
		 * registered, or the current engine state indicates that a wait is proper, the thread calls
		 * {@code WaitForEvent} instead. The thread is occupied until the wait completes, which is
		 * fine since the engine is inaccessible (except to certain callbacks) until it completes,
		 * anyway.
		 */
		try {
			init();
			while (!shuttingDown) {
				Entry next;
				while (null != (next = pollQueue())) {
					if (shuttingDown) {
						return;
					}
					try {
						//System.out.println("Executing: " + next);
						next.command.run();
						//System.out.println("Done");
					}
					catch (Throwable t) {
						Msg.error(this, "Task in executor threw: " + t);
					}
				}
				DebugStatus status = client.getControl().getExecutionStatus();
				if (status.shouldWait && status != DebugStatus.NO_DEBUGGEE ||
					waitRegistered.get()) {
					waitRegistered.set(false);
					try {
						getManager().waitForEventEx();
						//client.getControl().waitForEvent();
					}
					catch (COMException e) {
						Msg.error(this, "Error during WaitForEvents: " + e);
					}
				}
				else {
					try {
						client.dispatchCallbacks(100); // TODO: Better synchronization
					}
					catch (COMException e) {
						Msg.error(this, "Error during DispatchCallbacks: " + e);
					}
				}
			}
		}
		catch (Throwable t) {
			Msg.error(this, "Non-respawnable executor terminated unexpectedly", t);
			shuttingDown = true;
		}
	}

	@Override
	public void shutdown() {
		shuttingDown = true;
	}

	@Override
	public List<Runnable> shutdownNow() {
		shuttingDown = true;
		client.exitDispatch();
		thread.interrupt();
		List<Runnable> left = new ArrayList<>(queue.size());
		for (Entry ent : queue) {
			left.add(ent.command);
		}
		return left;
	}

	@Override
	public boolean isShutdown() {
		return shuttingDown;
	}

	@Override
	public boolean isTerminated() {
		return !thread.isAlive();
	}

	@Override
	public boolean awaitTermination(long timeout, TimeUnit unit) throws InterruptedException {
		long millis = TimeUnit.MILLISECONDS.convert(timeout, unit);
		thread.join(millis);
		return !thread.isAlive();
	}

	@Override
	public void execute(Runnable command) {
		execute(DEFAULT_PRIORITY, command);
	}

	/**
	 * Schedule a task with a given priority.
	 * 
	 * <p>
	 * Smaller priority values indicate earlier execution. The default priority is
	 * {@link #DEFAULT_PRIORITY}.
	 * 
	 * @param priority the priority
	 * @param command the task
	 */
	public void execute(int priority, Runnable command) {
		if (shuttingDown) {
			// TODO: Is this the correct exception?
			throw new RejectedExecutionException("Executor is shutting down");
		}
		if (!thread.isAlive()) {
			throw new RejectedExecutionException("Executor has terminated");
		}
		synchronized (queue) {
			queue.add(new Entry(priority, command));
			// TODO: Putting this in causes sync/output flushing problems
			//client.exitDispatch();
		}
	}

	public boolean isCurrentThread() {
		return thread.equals(Thread.currentThread());
	}

	/**
	 * Schedule a task with the given priority, taking a reference to the client.
	 * 
	 * <p>
	 * This is a convenience which spares a call to {@link #getClient()}. See
	 * {@link #execute(int, Runnable)} about priority.
	 * 
	 * @param priority the priority
	 * @param command the task
	 */
	public void execute(int priority, Consumer<DebugClient> command) {
		execute(priority, () -> command.accept(client));
	}

	public abstract DbgManager getManager();

	public abstract void setManager(DbgManager manager);
}
