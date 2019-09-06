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

import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.CancelledException;

/**
 * Create a "do nothing" task monitor that we can pass along to methods that
 * need a task monitor. This can be used when methods provide detailed
 * task progress information that we don't want to show the user.
 * <P>This  monitor can be configured to allow cancelling via {@link #setCancelEnabled(boolean)}.
 * If this cancelling is enabled, the the monitor may be cancelled programmatically.
 */
public class TaskMonitorAdapter implements TaskMonitor {

	private WeakSet<CancelledListener> listeners =
		WeakDataStructureFactory.createCopyOnReadWeakSet();

	private boolean cancelEnabled = false;
	private volatile boolean cancelled;

	/**
	 * Provides a static instance of <code>TaskMonitorAdapter</code>
	 * which is a non-cancellable task monitor with no visual components.
	 * @deprecated use {@link TaskMonitor#DUMMY} instead
	 */
	@Deprecated
	public static final TaskMonitor DUMMY_MONITOR = TaskMonitor.DUMMY;

	public TaskMonitorAdapter() {
		// do nothing
	}

	public TaskMonitorAdapter(boolean cancelEnabled) {
		this.cancelEnabled = cancelEnabled;
	}

	@Override
	public boolean isCancelled() {
		return cancelled;
	}

	@Override
	public void checkCanceled() throws CancelledException {
		if (cancelled) {
			throw new CancelledException();
		}
	}

	@Override
	public void setMessage(String message) {
		// do nothing
	}

	@Override
	public String getMessage() {
		return null;
	}

	@Override
	public void setProgress(long value) {
		// do nothing
	}

	public int getMinimum() {
		return 0;
	}

	public void setMinimum(int min) {
		// do nothing
	}

	@Override
	public long getMaximum() {
		return 0;
	}

	@Override
	public void initialize(long max) {
		// do nothing
	}

	@Override
	public void setMaximum(long max) {
		// do nothing
	}

	@Override
	public void setShowProgressValue(boolean showProgressValue) {
		// do nothing
	}

	@Override
	public void setIndeterminate(boolean indeterminate) {
		// do nothing
	}

	@Override
	public boolean isIndeterminate() {
		return false;
	}

	@Override
	public synchronized void setCancelEnabled(boolean enable) {
		cancelEnabled = enable;
	}

	@Override
	public synchronized boolean isCancelEnabled() {
		return cancelEnabled;
	}

	@Override
	public void cancel() {
		synchronized (this) {
			if (cancelled || !cancelEnabled) {
				return;
			}
			cancelled = true;
		}
		notifyChangeListeners();
	}

	@Override
	public void clearCanceled() {
		synchronized (this) {
			if (!cancelled) {
				return;
			}
			cancelled = false;
		}

		// TODO this seems like a mistake, to notify of 'cancelled' when clearning 
		notifyChangeListeners();
	}

	@Override
	public void incrementProgress(long incrementAmount) {
		// do nothing
	}

	@Override
	public long getProgress() {
		return NO_PROGRESS_VALUE;
	}

	protected synchronized void notifyChangeListeners() {
		for (CancelledListener listener : listeners) {
			listener.cancelled();
		}
	}

	@Override
	public synchronized void addCancelledListener(CancelledListener listener) {
		listeners.add(listener);
	}

	@Override
	public synchronized void removeCancelledListener(CancelledListener listener) {
		listeners.remove(listener);
	}
}
