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

import ghidra.util.exception.CancelledException;

/**
 * <CODE>TaskMonitor</CODE> provides an interface by means of which a
 * potentially long running task can show its progress and also check if the user
 * has cancelled the operation. 
 * <p>
 * Operations that support a task monitor should periodically
 * check to see if the operation has been cancelled and abort. If possible, the 
 * operation should also provide periodic progress information. If it can estimate a 
 * percentage done, then it should use the <code>setProgress(int)</code> method, 
 * otherwise it should just call the <code>setMessage(String)</code> method. 
 */
public interface TaskMonitor {

	public static final TaskMonitor DUMMY = new StubTaskMonitor();

	/**
	 * Returns the given task monitor if it is not {@code null}.  Otherwise, a {@link #DUMMY} 
	 * monitor is returned.
	 * @param tm the monitor to check for {@code null}
	 * @return a non-null task monitor
	 */
	public static TaskMonitor dummyIfNull(TaskMonitor tm) {
		return tm == null ? DUMMY : tm;
	}

	/** A value to indicate that this monitor has no progress value set */
	public static final int NO_PROGRESS_VALUE = -1;

	/**
	 * Returns true if the user has cancelled the operation
	 * 
	 * @return true if the user has cancelled the operation
	 */
	public boolean isCancelled();

	/**
	 * True (the default) signals to paint the progress information inside of the progress bar
	 * 
	 * @param showProgressValue true to paint the progress value; false to not
	 */
	public void setShowProgressValue(boolean showProgressValue);

	/**
	 * Sets the message displayed on the task monitor
	 * 
	 * @param message the message to display
	 */
	public void setMessage(String message);

	/**
	 * Gets the last set message of this monitor
	 * @return the message
	 */
	public String getMessage();

	/**
	 * Sets the current progress value
	 * @param value progress value
	 */
	public void setProgress(long value);

	/**
	 * Initialized this TaskMonitor to the given max values.  The current value of this monitor
	 * will be set to zero.
	 * 
	 * @param max maximum value for progress
	 */
	public void initialize(long max);

	/**
	 * Set the progress maximum value
	 * <p><b>
	 * Note: setting this value will reset the progress to be the max if the progress is currently
	 * greater than the new new max value.</b>
	 * @param max maximum value for progress
	 */
	public void setMaximum(long max);

	/** 
	 * Returns the current maximum value for progress
	 * @return the maximum progress value
	 */
	public long getMaximum();

	/**
	 * An indeterminate task monitor may choose to show an animation instead of updating progress 
	 * @param indeterminate true if indeterminate
	 */
	public void setIndeterminate(boolean indeterminate);

	/**
	 * Returns true if this monitor shows no progress
	 * @return true if this monitor shows no progress
	 */
	public boolean isIndeterminate();

	/**
	 * Check to see if this monitor has been canceled
	 * @throws CancelledException if monitor has been cancelled
	 */
	public void checkCanceled() throws CancelledException;

	/**
	 * A convenience method to increment the current progress by the given value
	 * @param incrementAmount The amount by which to increment the progress
	 */
	public void incrementProgress(long incrementAmount);

	/**
	 * Returns the current progress value or {@link #NO_PROGRESS_VALUE} if there is no value
	 * set
	 * @return the current progress value or {@link #NO_PROGRESS_VALUE} if there is no value
	 * set
	 */
	public long getProgress();

	/**
	 * Cancel the task
	 */
	public void cancel();

	/**
	 * Add cancelled listener
	 * @param listener the cancel listener
	 */
	public void addCancelledListener(CancelledListener listener);

	/**
	 * Remove cancelled listener
	 * @param listener the cancel listener
	 */
	public void removeCancelledListener(CancelledListener listener);

	/**
	 * Set the enablement of the Cancel button
	 * @param enable true means to enable the cancel button
	 */
	public void setCancelEnabled(boolean enable);

	/**
	 * Returns true if cancel ability is enabled
	 * @return true if cancel ability is enabled
	 */
	public boolean isCancelEnabled();

	/**
	 * Clear the cancellation so that this TaskMonitor may be reused
	 *
	 */
	public void clearCanceled();

}
