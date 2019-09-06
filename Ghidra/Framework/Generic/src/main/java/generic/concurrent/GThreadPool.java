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
package generic.concurrent;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import generic.util.NamedDaemonThreadFactory;
import ghidra.util.SystemUtilities;

/**
 * Class for managing and sharing thread pools. The GThreadPool is simplified version of the
 * ThreadPoolExecutor, which can be confusing to use with its many configuration parameters.
 * The GThreadPool has a simple behavior that is controlled by only two configuration parameters -
 * the minimum number of threads and the maximum number of threads.
 * <p>
 * The simple behavior for when new tasks are submitted:<br>
 *  1) If there any idle threads, use that thread.<br>
 *  2) If all existing threads are busy and the number of threads is less than max threads, add a 
 *     new thread and use it.<br>
 *  3) if all threads are busy and there are max number of threads, queue the item until a thread
 *     becomes free.<br>
 * <p>
 * The simple behavior for when tasks are completed by a thread:<br>
 *  1) If there are tasks in the queue, start processing a new item in the newly freed thread.<br>
 *  2) if there are more threads that min threads, allow this thread to die if no new 
 *     jobs arrive before
 *     the "KEEP ALIVE" time expires which is currently 15 seconds.<br>
 *  3) if there are min threads or less, allow this thread to wait forever for a new job 
 *     to arrive.<br>
 */
public class GThreadPool {
	private static final long DEFAULT_KEEP_ALIVE = 15;

	private static Map<String, GThreadPool> sharedPoolMap = new HashMap<>();

	private final String name;

	private final GThreadPoolExecutor executor;

	/**
	 * Creates a new, private thread pool with the given name.
	 * @param name the name of the thread pool
	 * @return a private GThreadPool with the given name.
	 */
	public static GThreadPool getPrivateThreadPool(String name) {
		return new GThreadPool(name);
	}

	/**
	 * Returns a shared GThreadPool.  If a shared GThreadPool already exists with the given name,
	 * it is returned.  Otherwise, a new shared GThreadPool is created and returned.
	 * @param name the name of the GThreadPool.
	 * @return a shared GThreadPool with the given name.
	 */
	public static GThreadPool getSharedThreadPool(String name) {
		GThreadPool threadPool = sharedPoolMap.get(name);
		if (threadPool == null) {
			threadPool = new GThreadPool(name);
		}
		return threadPool;
	}

	private GThreadPool(String name) {
		this.name = name;
		executor = new GThreadPoolExecutor();
		sharedPoolMap.put(name, this);
	}

	/**
	 * Sets the max number of threads to use in this thread pool.  The default is the number
	 * of processors + 1.
	 * @param maxThreadCount the maximum number of threads to use in this thread pool.
	 */
	public void setMaxThreadCount(int maxThreadCount) {
		executor.setMaxThreadCount(maxThreadCount);
	}

	/**
	 * Returns the minimum number of threads to keep alive in this thread pool.
	 * @return the minimum number of threads to keep alive in this thread pool.
	 */
	public int getMinThreadCount() {
		return executor.getMinThreadCount();
	}

	/**
	 * Sets the minimum number of threads to keep alive in this thread pool.
	 * @param minThreadCount the minimum number of threads to keep alive in this thread pool.
	 */
	public void setMinThreadCount(int minThreadCount) {
		executor.setMinThreadCount(minThreadCount);
	}

	/**
	 * Returns the maximum number of threads to use in this thread pool.
	 * @return the maximum number of threads to use in this thread pool.
	 */
	public int getMaxThreadCount() {
		return executor.getMaxThreadCount();
	}

	/**
	 * Submits a FutreTask to be executed by a thread in this thread pool.
	 * @param futureTask the future task to be executed.
	 */
	public void submit(FutureTask<?> futureTask) {
		executor.execute(futureTask);
	}

	/**
	 * Submits a runnable to be executed by this thread pool.
	 * @param task the runnable to be executed.
	 * @return a Future for that runnable.
	 */
	public Future<?> submit(Runnable task) {
		return executor.submit(task);
	}

	/**
	 * Submits a runnable to be executed by this thread pool.
	 * @param task the runnable to be executed.
	 * @param result the result to be returned after the runnable has executed.
	 * @return a Future for that runnable.
	 */
	public <T> Future<T> submit(Runnable task, T result) {
		return executor.submit(task, result);
	}

	/**
	 * Submits a callable to be executed by this thread pool.
	 * @param task the callable to be executed.
	 * @return a Future for that callable.
	 */
	public <T> Future<T> submit(Callable<T> task) {
		return executor.submit(task);
	}

	public void shutdownNow() {
		executor.shutdownNow();
	}

	/**
	 * Returns true if this is not a shared thread pool.
	 * 
	 * @return true if this is not a shared thread pool.
	 */
	public boolean isPrivate() {
		return !sharedPoolMap.containsKey(name);
	}

	/**
	 * Returns the {@link Executor} used by this thread pool.
	 * 
	 * <P>Note: normal usage of this thread pool contraindicates accessing the executor of 
	 * this pool.  For managing your own jobs, you should use the method on this class directly.
	 * The intent of this method is to provide access to the executor so that it may be 
	 * passed to other asynchronous APIs, such as the {@link CompletableFuture}.
	 * 
	 * @return the executor
	 */
	public Executor getExecutor() {
		return executor;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class GThreadPoolExecutor extends ThreadPoolExecutor {
		private volatile int maxThreadCount = SystemUtilities.getDefaultThreadPoolSize();
		private volatile int minThreadCount = 0;
		private AtomicInteger taskCount = new AtomicInteger();

		public GThreadPoolExecutor() {
			super(0, Integer.MAX_VALUE, DEFAULT_KEEP_ALIVE, TimeUnit.SECONDS,
				new LinkedBlockingQueue<Runnable>(), new NamedDaemonThreadFactory(name));
		}

		public int getMinThreadCount() {
			return minThreadCount;
		}

		public void setMinThreadCount(int minThreadCount) {
			this.minThreadCount = Math.max(minThreadCount, 0);
		}

		public int getMaxThreadCount() {
			return maxThreadCount;
		}

		public void setMaxThreadCount(int maxThreadCount) {
			this.maxThreadCount = Math.max(maxThreadCount, 1);
		}

		@Override
		public void execute(Runnable command) {
			growPoolIfNeeded();
			super.execute(command);
		}

		private void growPoolIfNeeded() {
			int count = taskCount.incrementAndGet();
			int corePoolSize = getCorePoolSize();

			if (corePoolSize >= maxThreadCount) {
				return;
			}
			if (isCurrentThreadInThisThreadPool()) {
				count--;
			}

			if (count > corePoolSize) {
				setCorePoolSize(corePoolSize + 1);
			}
		}

		private boolean isCurrentThreadInThisThreadPool() {
			return Thread.currentThread().getName().startsWith(name);
		}

		private void shrinkPoolIfNotBusy() {
			int count = taskCount.decrementAndGet();
			int corePoolSize = getCorePoolSize();
			if (corePoolSize <= minThreadCount) {
				return;
			}
			if (count < corePoolSize) {
				setCorePoolSize(corePoolSize - 1);
			}
		}

		@Override
		protected void afterExecute(Runnable r, Throwable t) {
			shrinkPoolIfNotBusy();
			super.afterExecute(r, t);
		}
	}
}
