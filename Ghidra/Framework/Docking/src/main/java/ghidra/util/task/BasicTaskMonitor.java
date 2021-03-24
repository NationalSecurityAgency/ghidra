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

import java.util.concurrent.atomic.AtomicBoolean;

import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.CancelledException;

/**
 * A task monitor that tracks all monitor state, but is not attached to any UI component
 * 
 * <p><b>Synchronization Policy</b>:<br>
 * We wish for this class to be performant.    Thus, we do not synchronize the methods of this
 * class, nor do we make the values thread visible via <code>volatile</code> or by any of 
 * the Java concurrent structures (e.g., {@link AtomicBoolean}).   In order to keep the values of
 * this class's fields update-to-date, we have chosen to synchronize the package-level client of
 * this class.  <b>If this class is ever made public, then most of the methods herein need to 
 * be synchronized to prevent race conditions and to provide visibility.
 */
class BasicTaskMonitor implements TaskMonitor {

	private WeakSet<CancelledListener> listeners =
		WeakDataStructureFactory.createCopyOnReadWeakSet();

	private String message;
	private long progress;
	private long maxProgress;

	private boolean cancelEnabled = true;
	private boolean isCancelled;
	private boolean isIndeterminate;

	@Override
	public void addCancelledListener(CancelledListener l) {
		listeners.add(l);
	}

	@Override
	public void removeCancelledListener(CancelledListener l) {
		listeners.remove(l);
	}

	@Override
	public void incrementProgress(long incrementAmount) {
		setProgress(progress + incrementAmount);
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
	public void checkCanceled() throws CancelledException {
		if (isCancelled) {
			throw new CancelledException();
		}
	}

	@Override
	public void setMessage(String message) {
		this.message = message;
	}

	@Override
	public String getMessage() {
		return message;
	}

	@Override
	public void setProgress(long value) {
		progress = value;
	}

	@Override
	public void initialize(long maxValue) {
		setMaximum(maxValue);
		setProgress(0);
		setIndeterminate(false);
	}

	@Override
	public void setMaximum(long max) {
		this.maxProgress = max;
		if (progress > max) {
			progress = max;
		}
	}

	@Override
	public void setIndeterminate(boolean indeterminate) {
		isIndeterminate = indeterminate;
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
	public void cancel() {
		boolean wasCancelled = isCancelled;
		isCancelled = true;
		if (!wasCancelled) {
			notifyCancelledListeners();
		}
	}

	@Override
	public void clearCanceled() {
		isCancelled = false;
	}

	@Override
	public long getMaximum() {
		return maxProgress;
	}

	@Override
	public boolean isIndeterminate() {
		return isIndeterminate;
	}

	@Override
	public void setShowProgressValue(boolean showProgressValue) {
		// stub
	}

	private void notifyCancelledListeners() {
		for (CancelledListener listener : listeners) {
			listener.cancelled();
		}
	}
}
