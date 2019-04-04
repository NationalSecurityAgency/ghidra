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
package ghidra.util.task;

import java.util.concurrent.atomic.AtomicInteger;

import javax.swing.SwingUtilities;

/**
 * Provides access to the {@link TaskMonitor} instance for the current thread. The first
 * time a monitor is requested via {@link #getMonitor()}, a "primary" monitor (one
 * that allows updating of task progress and status messages) is returned; all 
 * subsequent requests will return a "secondary" monitor, which only allows
 * status message updates. This is to keep the progress bar from being updated
 * simultaneously by multiple parties. 
 * <p>
 * Note: {@link TaskMonitor monitor} instances are registered with this service via the
 * {@link #register(TaskMonitor) setMonitor} call, and will be available to that thread until
 * the {@link #remove(int) remove} method is called. 
 * <p>
 * Note: Because monitor instances are managed by a {@link ThreadLocal} object, they will be 
 * cleaned up automatically by the GC when the thread is terminated. 
 */
public class TaskMonitorService {
	
	/**
	 * The {@link TaskMonitor} instance. ThreadLocal ensures that each thread has access
	 * to its own monitor.
	 */
	private static ThreadLocal<TaskMonitor> localMonitor = new ThreadLocal<TaskMonitor>() {

		/** 
		 * Force the initial value to be null so users will have to call 
		 * {@link TaskMonitorService#register(TaskMonitor) register} to assign one
		 * 
		 * @return null 
		 */
		@Override
		protected TaskMonitor initialValue() {
			return null;
		}
	};

	/**
	 * Unique id for each thread monitor that is assigned when a monitor is 
	 * {@link #register(TaskMonitor) registered}. This is to ensure that only clients who have 
	 * a valid id can remove a monitor.
	 */
	private static ThreadLocal<Integer> localMonitorId = new ThreadLocal<Integer>() {

		@Override
		protected Integer initialValue() {
			return nextId.getAndIncrement();
		}
	};

	/**
	 * Contains the next unique id for the monitor; this is updated each time a new monitor
	 * is registered with the service.
	 */
	private static final AtomicInteger nextId = new AtomicInteger(0);

	/**
	 * Returns the task monitor for the current thread. If one has not yet been registered,
	 * a {@link StubTaskMonitor stub monitor} is returned.
	 * 
	 * @return the task monitor
	 */
	public synchronized static TaskMonitor getMonitor() {
		
		if (localMonitor.get() == null) {
			
			// If no monitor is available, just return a stub. The alternative is to throw an 
			// exception but this isn't considered an error condition in all cases. 
			localMonitor.set(new StubTaskMonitor());
		}
		
		// If the monitor has already been initialized, return the secondary monitor to prevent
		// the caller from hijacking the progress bar
		if (localMonitor.get().isInitialized()) {
			return localMonitor.get().getSecondaryMonitor();
		}

		// This ensures that the next time this method is called, the service
		// will return the secondary monitor
		localMonitor.get().setInitialized(true);

		return localMonitor.get();
	}

	/**
	 * Sets the given monitor for this thread
	 * 
	 * @param monitor the task monitor to register
	 * @return the unique id for the monitor
	 */
	public static int register(TaskMonitor monitor) {
		
		// Don't allow callers to register a monitor if on the swing thread
		if (SwingUtilities.isEventDispatchThread()) {
			throw new IllegalArgumentException("Attempting to set a monitor in the Swing thread!");
		}
		
		// Don't allow users to register a monitor if there is already one registered for this 
		// thread
		if (localMonitor.get() != null) {
			throw new IllegalArgumentException("Task monitor already assigned to this thread");
		}

		localMonitor.set(monitor);

		return localMonitorId.get();

	}
	
	/**
	 * Removes the monitor from the thread local object. To protect against clients cavalierly
	 * removing monitors, a valid monitor id must be provided; this is generated at the time
	 * of monitor {@link #register(TaskMonitor) registration}.
	 * <p>
	 * Note: This should generally not need to be called as the GC will clean up thread local 
	 * objects when the associated thread is finished.
	 * 
	 * @param monitorId the unique ID for the monitor to be removed
	 */
	public static void remove(int monitorId) {

		if (monitorId != localMonitorId.get()) {
			throw new IllegalArgumentException("Invalid monitor id for this thread: " + monitorId);
		}

		localMonitor.remove();
	}
		
	/**
	 * Hide the constructor - this should not be instantiated
	 */
	private TaskMonitorService() {
		// nothing to do
	}
}
