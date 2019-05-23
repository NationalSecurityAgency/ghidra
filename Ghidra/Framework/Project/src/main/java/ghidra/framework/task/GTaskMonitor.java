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
package ghidra.framework.task;

import ghidra.framework.task.gui.GProgressBar;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;

/**
 * Implementation of a TaskMontor that can be "attached" to a GProgressBar.
 *
 * The GTaskMonitor is a non-gui object for tracking the progress of a GTaskGroup or GTask.  It
 * is created by the GTaskManager as tasks are scheduled.  GUIs that wish to display the progress
 * of the groups and tasks can set a GProgressBar into a GTaskMonitor and it will display the
 * progress.
 *
 */
public class GTaskMonitor implements TaskMonitor, CancelledListener {
	private GProgressBar progressBar;
	private volatile boolean isCancelled;
	private boolean showProgressValue;
	private volatile String message;
	private volatile long progress;
	private volatile long max;
	private boolean indeterminate;
	private boolean cancelEnabled = true;

	public GTaskMonitor() {
	}

	@Override
	public boolean isCancelled() {
		return isCancelled;
	}

	@Override
	public void setShowProgressValue(boolean showProgressValue) {
		this.showProgressValue = showProgressValue;
		if (progressBar != null) {
			progressBar.setShowProgressValue(showProgressValue);
		}
	}

	@Override
	public void setMessage(String message) {
		this.message = message;
		if (progressBar != null) {
			progressBar.setMessage(message);
		}
	}

	@Override
	public void setProgress(long value) {
		this.progress = value;
		if (progressBar != null) {
			progressBar.setProgress(value);
		}
	}

	@Override
	public void initialize(long maxValue) {
		this.max = maxValue;
		this.progress = 0;
		if (progressBar != null) {
			progressBar.initialize(maxValue);
		}
	}

	@Override
	public void setMaximum(long max) {
		this.max = max;
		if (progressBar != null) {
			progressBar.setMaximum(max);
		}

	}

	@Override
	public long getMaximum() {
		return max;
	}

	@Override
	public void setIndeterminate(boolean indeterminate) {
		this.indeterminate = indeterminate;
		if (progressBar != null) {
			progressBar.setIndeterminate(indeterminate);
		}
	}

	@Override
	public boolean isIndeterminate() {
		return indeterminate;
	}

	@Override
	public void checkCanceled() throws CancelledException {
		if (isCancelled) {
			setMessage("CANCELLED!");
			throw new CancelledException();
		}
	}

	@Override
	public void incrementProgress(long incrementAmount) {
		this.progress += incrementAmount;
		if (progressBar != null) {
			progressBar.incrementProgress(incrementAmount);
		}
	}

	@Override
	public long getProgress() {
		return progress;
	}

	@Override
	public void cancel() {
		if (cancelEnabled) {
			isCancelled = true;
		}
	}

	@Override
	public void addCancelledListener(CancelledListener mcl) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeCancelledListener(CancelledListener mcl) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setCancelEnabled(boolean enable) {
		cancelEnabled = enable;
	}

	@Override
	public boolean isCancelEnabled() {
		return cancelEnabled;
	}

	@Override
	public void clearCanceled() {
		isCancelled = false;
	}

	public boolean isInderminate() {
		return indeterminate;
	}

	public boolean isShowingProgressValue() {
		return showProgressValue;
	}

	@Override
	public String getMessage() {
		return message;
	}

	@Override
	public void cancelled() {
		cancel();
	}

	/**
	 * Set the GProgressBar to use to display the progress.
	 * @param gProgressBar the GProgressBar to use.
	 */
	public void setProgressBar(GProgressBar gProgressBar) {
		progressBar = gProgressBar;
		progressBar.initialize(max);
		progressBar.setProgress(progress);
		progressBar.setMessage(message);
		progressBar.setCancelledListener(this);
	}

}
