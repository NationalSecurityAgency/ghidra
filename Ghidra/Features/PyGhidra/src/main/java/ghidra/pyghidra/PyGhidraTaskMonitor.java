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
package ghidra.pyghidra;

import java.util.Timer;
import java.util.TimerTask;

import org.apache.commons.lang3.function.TriConsumer;

import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link TaskMonitor} for use by PyGhidra, which features a cancellation timer and a change 
 * callback mechanism
 */
public class PyGhidraTaskMonitor implements TaskMonitor {

	private String message;
	private long progress;
	private long maxProgress;
	private boolean isIndeterminate;
	private volatile boolean isCancelled;

	private Timer timer = new Timer();
	private WeakSet<CancelledListener> listeners =
		WeakDataStructureFactory.createCopyOnReadWeakSet();
	private TriConsumer<String, Long, Long> changeCallback;

	/**
	 * Creates a new {@link PyGhidraTaskMonitor}
	 *  
	 * @param timeoutSecs The number of seconds before a cancellation timeout is triggered, or
	 *   {@code null} for no timeout
	 * @param changeCallback A function that gets called any time a change to the monitor occurred,
	 *   or {@code null} for no callback
	 */
	public PyGhidraTaskMonitor(Integer timeoutSecs,
			TriConsumer<String, Long, Long> changeCallback) {
		isCancelled = false;
		if (timeoutSecs != null) {
			timer.schedule(new PyGhidraTimeOutTask(), timeoutSecs * 1000);
		}
		this.changeCallback = changeCallback;
	}

	@Override
	public void initialize(long maxValue) {
		setMaximum(maxValue);
		setProgress(0);
		setIndeterminate(false);
	}

	@Override
	public void setMessage(String message) {
		this.message = message;
		if (changeCallback != null) {
			changeCallback.accept(message, progress, maxProgress);
		}
	}

	@Override
	public String getMessage() {
		return message;
	}

	@Override
	public void incrementProgress(long incrementAmount) {
		setProgress(progress + incrementAmount);
	}

	@Override
	public void setProgress(long value) {
		progress = value;
		if (changeCallback != null) {
			changeCallback.accept(message, progress, maxProgress);
		}
	}

	@Override
	public long getProgress() {
		return progress;
	}

	@Override
	public boolean isCancelled() {
		return isCancelled;
	}

	@Override
	public void setMaximum(long max) {
		this.maxProgress = max;
		if (progress > max) {
			progress = max;
		}
		if (changeCallback != null) {
			changeCallback.accept(message, progress, maxProgress);
		}
	}

	@Override
	public long getMaximum() {
		return maxProgress;
	}

	@Override
	public void setIndeterminate(boolean indeterminate) {
		isIndeterminate = indeterminate;
	}

	@Override
	public boolean isIndeterminate() {
		return isIndeterminate;
	}

	@Override
	public void checkCanceled() throws CancelledException {
		if (isCancelled()) {
			throw new CancelledException();
		}
	}

	@Override
	public void clearCanceled() {
		isCancelled = false;
	}

	@Override
	public void cancel() {
		timer.cancel(); // Terminate the timer thread
		isCancelled = true;
	}

	@Override
	public void setCancelEnabled(boolean enable) {
		// stub
	}

	@Override
	public boolean isCancelEnabled() {
		return true;
	}

	@Override
	public void setShowProgressValue(boolean showProgressValue) {
		// stub
	}

	@Override
	public void addCancelledListener(CancelledListener listener) {
		listeners.add(listener);
	}

	@Override
	public void removeCancelledListener(CancelledListener listener) {
		listeners.remove(listener);
	}

	private class PyGhidraTimeOutTask extends TimerTask {
		@Override
		public void run() {
			PyGhidraTaskMonitor.this.cancel();
		}
	}
}

