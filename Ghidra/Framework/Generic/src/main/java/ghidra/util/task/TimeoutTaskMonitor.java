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

import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.TimeoutException;
import ghidra.util.timer.GTimer;
import ghidra.util.timer.GTimerMonitor;
import utility.function.Callback;
import utility.function.Dummy;

/**
 * A task monitor that allows clients the ability to specify a timeout after which this monitor
 * will be cancelled.
 * 
 * <P>This monitor can wrap an existing monitor.
 * 
 * <P>You can call {@link #setTimeoutListener(Callback)} to get a notification that the monitor
 * timed-out.  In order to prevent this from firing after your work is finished normally, call
 * {@link #finished()}.
 */
public class TimeoutTaskMonitor implements TaskMonitor {

	/**
	 * Creates a timeout task monitor that will be cancelled after the specified timeout.
	 * 
	 * @param timeout the timeout value
	 * @param timeUnit the timeout time unit
	 * @return the newly created monitor
	 */
	public static TimeoutTaskMonitor timeoutIn(long timeout, TimeUnit timeUnit) {

		TaskMonitor delegate = new TaskMonitorAdapter(true);
		TimeoutTaskMonitor timeoutMonitor = timeoutIn(timeout, timeUnit, delegate);
		return timeoutMonitor;
	}

	/**
	 * Creates a timeout task monitor that will be cancelled after the specified timeout.  The
	 * created monitor wraps the given monitor, calling cancel on the given monitor when the
	 * timeout is reached.  This method allows you to use an existing monitor while adding
	 * the timeout feature.
	 * 
	 * @param timeout the timeout value
	 * @param timeUnit the timeout time unit
	 * @param monitor the monitor to wrap
	 * @return the newly created monitor
	 */
	public static TimeoutTaskMonitor timeoutIn(long timeout, TimeUnit timeUnit,
			TaskMonitor monitor) {

		TaskMonitor delegate = Objects.requireNonNull(monitor);
		if (!delegate.isCancelEnabled()) {
			// could be a dummy monitor; create a monitor we can cancel
			delegate = new TaskMonitorAdapter(true);
		}

		TimeoutTaskMonitor timeoutMonitor = new TimeoutTaskMonitor(delegate, timeout, timeUnit);
		return timeoutMonitor;
	}

	private TaskMonitor delegate;
	private GTimerMonitor timerMonitor;
	private long timeout;
	private TimeUnit timeUnit;

	private AtomicBoolean didTimeout = new AtomicBoolean(false);
	private Callback timeoutCallback = Callback.dummy();

	TimeoutTaskMonitor(TaskMonitor delegate, long timeout, TimeUnit timeUnit) {

		Objects.requireNonNull(delegate);
		SystemUtilities.assertTrue(delegate != TaskMonitor.DUMMY,
			"TaskMonitor.DUMMY is not cancellable.  Please pass a cancellable monitor.");
		SystemUtilities.assertTrue(timeout > 0, "Timeout must be greater than 0");

		this.timeout = timeout;
		this.timeUnit = timeUnit;
		this.delegate = delegate;

		long millis = TimeUnit.MILLISECONDS.convert(timeout, timeUnit);
		timerMonitor = GTimer.scheduleRunnable(millis, () -> timeout());
	}

	/**
	 * Sets a callback function that will be called if the timeout is reached.
	 * 
	 * @param timeoutCallback the callback to call
	 */
	public void setTimeoutListener(Callback timeoutCallback) {

		this.timeoutCallback = Dummy.ifNull(timeoutCallback);
	}

	/**
	 * Returns true if this monitor has timed-out
	 * @return true if this monitor has timed-out
	 */
	public boolean didTimeout() {
		return didTimeout.get();
	}

	public void finished() {
		this.timeoutCallback = Callback.dummy();
	}

//==================================================================================================
// TaskMonitor Methods
//==================================================================================================	

	@Override
	public boolean isCancelled() {
		return delegate.isCancelled();
	}

	@Override
	public void setShowProgressValue(boolean showProgressValue) {
		delegate.setShowProgressValue(showProgressValue);
	}

	@Override
	public void setMessage(String message) {
		delegate.setMessage(message);
	}

	@Override
	public String getMessage() {
		return delegate.getMessage();
	}

	@Override
	public void setProgress(long value) {
		delegate.setProgress(value);
	}

	@Override
	public void initialize(long max) {
		delegate.initialize(max);
	}

	@Override
	public void setMaximum(long max) {
		delegate.setMaximum(max);
	}

	@Override
	public long getMaximum() {
		return delegate.getMaximum();
	}

	@Override
	public void setIndeterminate(boolean indeterminate) {
		delegate.setIndeterminate(indeterminate);
	}

	@Override
	public boolean isIndeterminate() {
		return delegate.isIndeterminate();
	}

	@Override
	public void checkCanceled() throws CancelledException {
		if (didTimeout()) {
			throw new TimeoutException(
				"Operation cancelled due to timeout of " + timeout + " " + timeUnit.toString());
		}
		delegate.checkCanceled();
	}

	@Override
	public void incrementProgress(long incrementAmount) {
		delegate.incrementProgress(incrementAmount);
	}

	@Override
	public long getProgress() {
		return delegate.getProgress();
	}

	private void timeout() {
		didTimeout.set(true);
		timeoutCallback.call();
		cancel();
	}

	@Override
	public void cancel() {
		timerMonitor.cancel(); // in case a client cancels us
		delegate.cancel();
	}

	@Override
	public void addCancelledListener(CancelledListener listener) {
		delegate.addCancelledListener(listener);
	}

	@Override
	public void removeCancelledListener(CancelledListener listener) {
		delegate.removeCancelledListener(listener);
	}

	@Override
	public void setCancelEnabled(boolean enable) {
		delegate.setCancelEnabled(enable);
	}

	@Override
	public boolean isCancelEnabled() {
		return delegate.isCancelEnabled();
	}

	@Override
	public void clearCanceled() {
		delegate.clearCanceled();
	}
}
