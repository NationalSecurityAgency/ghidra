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

import java.util.concurrent.atomic.*;

import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.CancelledException;

/**
 * A task monitor that tracks all monitor state, but is not attached to any UI component
 */
class BasicTaskMonitor implements TaskMonitor {

	private WeakSet<CancelledListener> listeners =
		WeakDataStructureFactory.createCopyOnReadWeakSet();

	private AtomicReference<String> message = new AtomicReference<>();
	private AtomicLong progress = new AtomicLong();
	private AtomicLong maxProgress = new AtomicLong();

	private AtomicBoolean cancelEnabled = new AtomicBoolean(true);
	private AtomicBoolean isCancelled = new AtomicBoolean(false);
	private AtomicBoolean isIndeterminate = new AtomicBoolean(false);

	@Override
	public void addCancelledListener(CancelledListener mcl) {
		listeners.add(mcl);
	}

	@Override
	public void removeCancelledListener(CancelledListener mcl) {
		listeners.remove(mcl);
	}

	@Override
	public void incrementProgress(long incrementAmount) {
		setProgress(progress.get() + incrementAmount);
	}

	@Override
	public long getProgress() {
		return progress.get();
	}

	@Override
	public boolean isCancelled() {
		return isCancelled.get();
	}

	@Override
	public void checkCanceled() throws CancelledException {
		if (isCancelled.get()) {
			throw new CancelledException();
		}
	}

	@Override
	public void setMessage(String message) {
		this.message.set(message);
	}

	@Override
	public String getMessage() {
		return message.get();
	}

	@Override
	public void setProgress(long value) {
		progress.set(value);
	}

	@Override
	public void initialize(long maxValue) {
		setMaximum(maxValue);
		setProgress(0);
	}

	@Override
	public void setMaximum(long max) {
		this.maxProgress.set(max);
		if (progress.get() > max) {
			progress.set(max);
		}
	}

	@Override
	public void setIndeterminate(boolean indeterminate) {
		isIndeterminate.set(indeterminate);
	}

	@Override
	public void setCancelEnabled(boolean enable) {
		cancelEnabled.set(enable);
	}

	@Override
	public boolean isCancelEnabled() {
		return cancelEnabled.get();
	}

	@Override
	public void cancel() {
		boolean wasCancelled = isCancelled.getAndSet(true);
		if (!wasCancelled) {
			notifyChangeListeners();
		}
	}

	@Override
	public void clearCanceled() {
		isCancelled.set(false);
	}

	@Override
	public long getMaximum() {
		return maxProgress.get();
	}

	@Override
	public boolean isIndeterminate() {
		return isIndeterminate.get();
	}

	@Override
	public void setShowProgressValue(boolean showProgressValue) {
		// stub
	}

	private synchronized void notifyChangeListeners() {
		for (CancelledListener listener : listeners) {
			listener.cancelled();
		}
	}
}
