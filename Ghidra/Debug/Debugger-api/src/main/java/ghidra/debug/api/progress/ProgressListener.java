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
package ghidra.debug.api.progress;

/**
 * A listener for events on the progress service, including updates to task progress
 */
public interface ProgressListener {
	/**
	 * Describes how or why a task monitor was disposed
	 */
	enum Disposal {
		/**
		 * The monitor was properly closed
		 */
		CLOSED,
		/**
		 * The monitor was <em>not</em> closed. Instead, it was cleaned by the garbage collector.
		 */
		CLEANED;
	}

	/**
	 * A new task monitor has been created
	 * 
	 * <p>
	 * The subscriber ought to display the monitor as soon as is reasonable. Optionally, a
	 * subscriber may apply a grace period, e.g., half a second, before displaying it, in case it is
	 * quickly disposed.
	 * 
	 * @param monitor a means of retrieving messages and progress about the task
	 */
	void monitorCreated(MonitorReceiver monitor);

	/**
	 * A task monitor has been disposed
	 * 
	 * @param monitor the receiver for the disposed monitor
	 * @param disposal why it was disposed
	 */
	void monitorDisposed(MonitorReceiver monitor, Disposal disposal);

	/**
	 * A task has updated a monitor's message
	 * 
	 * @param monitor the receiver whose monitor's message changed
	 * @param message the new message
	 */
	void messageUpdated(MonitorReceiver monitor, String message);

	/**
	 * A task has reported an error
	 * 
	 * @param monitor the receiver for the task reporting the error
	 * @param error the exception representing the error
	 */
	void errorReported(MonitorReceiver monitor, Throwable error);

	/**
	 * A task's progress has updated
	 * 
	 * <p>
	 * Note the subscriber may need to use {@link MonitorReceiver#getMaximum()} to properly update
	 * the display.
	 * 
	 * @param monitor the receiver whose monitor's progress changed
	 * @param progress the new progress value
	 */
	void progressUpdated(MonitorReceiver monitor, long progress);

	/**
	 * Some other attribute has been updated
	 * 
	 * <ul>
	 * <li>cancelled</li>
	 * <li>cancel enabled</li>
	 * <li>indeterminate</li>
	 * <li>maximum</li>
	 * <li>show progress value in percent string</li>
	 * </ul>
	 * 
	 * @param monitor the receiver whose monitor's attribute(s) changed
	 */
	void attributeUpdated(MonitorReceiver monitor);
}
