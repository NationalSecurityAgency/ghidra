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

import ghidra.util.task.TaskMonitor;

import java.util.Comparator;
import java.util.concurrent.PriorityBlockingQueue;

/**
 * Executes a single job at a time in priority order.
 * 
 * @see Worker
 */
public class PriorityWorker extends AbstractWorker<PriorityJob> {

	/**
	 * Creates a PriorityWorker that will use a <b>shared</b> thread pool to process jobs.  
	 * Also, threads created using this constructor are not persistent.
	 * 
	 * @param name the name of the shared thread pool.
	 * @param monitor the monitor used to cancel jobs.
	 */
	public PriorityWorker(String name, TaskMonitor monitor) {
		super(new PriorityBlockingQueue<PriorityJob>(11, new PriorityJobComparator()), false, name,
			true /* shared */, monitor);
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
	public PriorityWorker(String name, boolean isPersistentThread, boolean useSharedThreadPool,
			TaskMonitor monitor) {
		super(new PriorityBlockingQueue<PriorityJob>(11, new PriorityJobComparator()),
			isPersistentThread, name, useSharedThreadPool, monitor);
	}

	@Override
	public synchronized void schedule(PriorityJob job) {
		super.schedule(job);
	}

	private static class PriorityJobComparator implements Comparator<PriorityJob> {
		@Override
		public int compare(PriorityJob o1, PriorityJob o2) {
			long priority1 = o1.getPriority();
			long priority2 = o2.getPriority();

			if (priority1 > priority2) {
				return 1;
			}
			else if (priority1 < priority2) {
				return -1;
			}
			return 0;
		}
	}
}
