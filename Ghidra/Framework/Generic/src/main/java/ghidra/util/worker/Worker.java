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
package ghidra.util.worker;

import java.util.concurrent.LinkedBlockingQueue;

import ghidra.util.Swing;
import ghidra.util.SystemUtilities;
import ghidra.util.task.TaskMonitor;

/**
 * Executes a single job at a time in FIFO order.
 * 
 * @see PriorityWorker
 */
public class Worker extends AbstractWorker<Job> {

	/**
	 * A convenience method to create a Worker that uses a shared thread pool for performing
	 * operations for GUI clients in a background thread 
	 * 
	 * <P>Note: the shared thread pool of the worker created here has a max number of 
	 * threads as defined by {@link SystemUtilities#getDefaultThreadPoolSize()}.   If there is
	 * a point in time where we notice contention in thread due to too many clients of this
	 * method (i.e., too many tasks are blocking because the thread pool is full), then we 
	 * can update the size of the thread pool for this Worker.
	 * 
	 * @return the new worker
	 */
	public static Worker createGuiWorker() {
		return new Worker(Swing.GSWING_THREAD_POOL_NAME);
	}

	/**
	 * Creates a Worker that will use a <b>shared</b> thread pool to process jobs.  Also, threads
	 * created using this constructor are not persistent.   Use this constructor when you do 
	 * not have a {@link TaskMonitor} that wants updates from this worker.
	 * 
	 * @param name the name of the shared thread pool.
	 */
	public Worker(String name) {
		super(new LinkedBlockingQueue<Job>(), false /* not persistent */, name, true /* shared */,
			TaskMonitor.DUMMY);
	}

	/**
	 * Creates a Worker that will use a <b>shared</b> thread pool to process jobs.  Also, threads
	 * created using this constructor are not persistent.
	 * 
	 * @param name the name of the shared thread pool.
	 * @param monitor the monitor used to cancel jobs.
	 */
	public Worker(String name, TaskMonitor monitor) {
		super(new LinkedBlockingQueue<Job>(), false /* not persistent */, name, true /* shared */,
			monitor);
	}

	/**
	 * This constructor allows you to change persistence and shared thread pool usage.
	 * 
	 * @param name the name of the shared thread pool.
	 * @param isPersistentThread if true, the worker thread will stay around when idle;
	 *             false means that the thread will go away if not needed. Should be true for 
	 *             high frequency usage.
	 * @param useSharedThreadPool true signals to use the given name to find/create a thread pool 
	 *             that can be shared throughout the system.
	 * @param monitor the monitor used to cancel jobs.
	 */
	public Worker(String name, boolean isPersistentThread, boolean useSharedThreadPool,
			TaskMonitor monitor) {
		super(new LinkedBlockingQueue<Job>(), isPersistentThread, name, useSharedThreadPool,
			monitor);
	}

}
