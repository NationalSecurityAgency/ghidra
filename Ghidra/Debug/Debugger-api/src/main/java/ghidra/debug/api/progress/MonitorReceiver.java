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

import ghidra.debug.api.progress.ProgressListener.Disposal;
import ghidra.util.task.TaskMonitor;

/**
 * The subscriber side of a published {@link TaskMonitor}
 * 
 * <p>
 * This only gives a subset of the expected task monitor interface. This is the subset a
 * <em>user</em> would need to monitor and/or cancel the task. All the mechanisms for updating the
 * monitor are only available to the publishing client.
 */
public interface MonitorReceiver {
	/**
	 * Get the current message for the monitor
	 * 
	 * @return the message
	 */
	String getMessage();

	/**
	 * Check if the monitor indicates progress at all
	 * 
	 * <p>
	 * If the task is indeterminate, then its {@link #getMaximum()} and {@link #getProgress()}
	 * methods are meaningless.
	 * 
	 * @return true if indeterminate (no progress shown), false if determinate (progress shown)
	 */
	boolean isIndeterminate();

	/**
	 * Get the maximum value of progress
	 * 
	 * <p>
	 * The implication is that when {@link #getProgress()} returns the maximum, the task is
	 * complete.
	 * 
	 * @return the maximum progress
	 */
	long getMaximum();

	/**
	 * Get the progress value, if applicable
	 * 
	 * @return the progress, or {@link TaskMonitor#NO_PROGRESS_VALUE} if un-set or not applicable
	 */
	long getProgress();

	/**
	 * Check if the task can be cancelled
	 * 
	 * @return true if cancel is enabled, false if not
	 */
	boolean isCancelEnabled();

	/**
	 * Request the task be cancelled
	 * 
	 * <p>
	 * Note it is up to the client publishing the task to adhere to this request. In general, the
	 * computation should occasionally call {@link TaskMonitor#checkCancelled()}. In particular, the
	 * subscribing client <em>cannot</em> presume the task is cancelled purely by virtue of calling
	 * this method successfully. Instead, it should listen for
	 * {@link ProgressListener#monitorDisposed(MonitorReceiver, Disposal)}.
	 */
	void cancel();

	/**
	 * Check if the task is cancelled
	 * 
	 * @return true if cancelled, false if not
	 */
	boolean isCancelled();

	/**
	 * Check if the monitor is still valid
	 * 
	 * <p>
	 * A monitor becomes invalid when it is closed or cleaned.
	 * 
	 * @return true if still valid, false if invalid
	 */
	boolean isValid();

	/**
	 * Check if the monitor should be rendered with the progress value
	 * 
	 * <p>
	 * Regardless of this value, the monitor will render a progress bar and a numeric percentage. If
	 * this is set to true (the default), the it will also display "{progress} of {maximum}" in
	 * text.
	 * 
	 * @return true to render the actual progress value, false for only a percentage.
	 */
	boolean isShowProgressValue();
}
