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
package agent.lldb.gadp.impl;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

import agent.lldb.lldb.DebugClient;
import agent.lldb.lldb.DebugClient.DebugStatus;
import agent.lldb.manager.LldbManager;
import ghidra.util.Msg;

/**
 * A single-threaded executor which creates and exclusively accesses the {@code lldb} client.
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
		return client;
	}

	public void cancelWait() {
		waitRegistered.set(false);
	}

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

				DebugStatus status = client.getExecutionStatus();
				if (status.shouldWait && status != DebugStatus.NO_DEBUGGEE ||
					waitRegistered.get()) {
					waitRegistered.set(false);
					getManager().waitForEventEx();
					//client.getControl().waitForEvent();
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
	 * @param priority the priority
	 * @param command the task
	 */
	public void execute(int priority, Runnable command) {
		if (shuttingDown) {
			throw new RejectedExecutionException("Executor is shutting down");
		}
		if (!thread.isAlive()) {
			throw new RejectedExecutionException("Executor has terminated");
		}
		synchronized (queue) {
			queue.add(new Entry(priority, command));
		}
	}

	public boolean isCurrentThread() {
		return thread.equals(Thread.currentThread());
	}

	/**
	 * Schedule a task with the given priority, taking a reference to the client.
	 * 
	 * @param priority the priority
	 * @param command the task
	 */
	public void execute(int priority, Consumer<DebugClient> command) {
		execute(priority, () -> command.accept(client));
	}

	public abstract LldbManager getManager();

	public abstract void setManager(LldbManager manager);
}
