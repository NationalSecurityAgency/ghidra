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
package ghidra.framework.data;

import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

class LockingTaskMonitor implements TaskMonitor {

	private DomainObjectAdapterDB dobj;
	private final String title;
	private boolean isCanceled = false;
	private boolean cancelEnabled = true;
	private final boolean hasProgress;
	private long maxProgress;
	private long curProgress;
	private boolean indeterminate;
	private boolean showProgressValue = true;
	private String msg;
	private MyTaskDialog taskDialog;

	/**
	 * Constructs a locking task handler for a locked domain object.  The
	 * {@link #releaseLock()} method must be invoked to dispose this object and release the
	 * lock.  This should be done in a try/finally block to avoid accidentally locking the
	 * domain object indefinitely.
	 *
	 * @param dobj domain object
	 * @param hasProgress true if this monitor has progress
	 * @param title task title
	 */
	LockingTaskMonitor(DomainObjectAdapterDB dobj, boolean hasProgress, String title) {
		this.dobj = dobj;
		this.hasProgress = hasProgress;
		this.title = title;
	}

	DomainObjectAdapterDB getDomainObject() {
		return dobj;
	}

	/**
	 * Display a modal task dialog associated with this locking task.
	 * This method will not return until the task has completed and the
	 * lock has been released.
	 */
	void waitForTaskCompletion() {
		synchronized (this) {
			if (dobj == null) {
				return;
			}
			if (taskDialog == null) {
				taskDialog = new MyTaskDialog();
			}
			else {
				try {
					// dialog already displayed - wait for releaseLock to occur
					wait();
				}
				catch (InterruptedException e) {
					// ignore
				}
				return;
			}
		}

		// show dialog without synchronization
		MyTaskDialog dialog = taskDialog;
		if (dialog != null) {
			SystemUtilities.runSwingNow(() -> dialog.show(0));
		}
	}

	@Override
	public synchronized boolean isCancelled() {
		return taskDialog != null ? taskDialog.isCancelled() : isCanceled;
	}

	/**
	 * Release associated domain object lock and close dialog.
	 * All blocked waits will be notified.
	 */
	synchronized void releaseLock() {
		if (dobj != null) {
			dobj.unlock(this);
			dobj = null;
		}
		if (taskDialog != null) {
			taskDialog.taskProcessed();
			taskDialog = null;
		}
		notifyAll();
	}

	@Override
	public synchronized void setMessage(String msg) {
		this.msg = msg;
		if (taskDialog != null) {
			taskDialog.setMessage(msg);
		}
	}

	@Override
	public synchronized String getMessage() {
		return msg;
	}

	@Override
	public synchronized void setProgress(long value) {
		this.curProgress = value;
		if (taskDialog != null) {
			taskDialog.setProgress(value);
		}
	}

	@Override
	public synchronized void initialize(long max) {
		setMaximum(max);
		setProgress(0);
	}

	@Override
	public synchronized void setMaximum(long max) {
		this.maxProgress = max;
		if (taskDialog != null) {
			taskDialog.setMaximum(max);
		}
	}

	@Override
	public long getMaximum() {
		return maxProgress;
	}

	@Override
	public void setShowProgressValue(boolean showProgressValue) {
		this.showProgressValue = showProgressValue;
		if (taskDialog != null) {
			taskDialog.setShowProgressValue(showProgressValue);
		}
	}

	@Override
	public void setIndeterminate(boolean indeterminate) {
		this.indeterminate = indeterminate;
		if (taskDialog != null) {
			taskDialog.setIndeterminate(indeterminate);
		}
	}

	@Override
	public boolean isIndeterminate() {
		return indeterminate;
	}

	@Override
	public synchronized void setCancelEnabled(boolean enable) {
		this.cancelEnabled = enable;
		if (taskDialog != null) {
			taskDialog.setCancelEnabled(enable);
		}
	}

	@Override
	public synchronized boolean isCancelEnabled() {
		return taskDialog != null ? taskDialog.isCancelEnabled() : cancelEnabled;
	}

	@Override
	public synchronized void cancel() {
		this.isCanceled = true;
		if (taskDialog != null) {
			taskDialog.cancel();
		}
	}

	@Override
	public void clearCanceled() {
		this.isCanceled = false;
		if (taskDialog != null) {
			taskDialog.clearCanceled();
		}
	}

	@Override
	public void checkCanceled() throws CancelledException {
		if (isCancelled()) {
			throw new CancelledException();
		}
	}

	@Override
	public void incrementProgress(long incrementAmount) {
		setProgress(curProgress + incrementAmount);
	}

	@Override
	public long getProgress() {
		return curProgress;
	}

	private class MyTaskDialog extends TaskDialog {

		MyTaskDialog() {
			super(title, true, true, hasProgress);
			setCancelEnabled(cancelEnabled);
			if (hasProgress) {
				initialize(maxProgress);
				setProgress(curProgress);
				setIndeterminate(indeterminate);
				setShowProgressValue(showProgressValue);
			}
			if (msg != null) {
				setMessage(msg);
			}
		}

	}

	@Override
	public void addCancelledListener(CancelledListener listener) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeCancelledListener(CancelledListener listener) {
		throw new UnsupportedOperationException();
	}
}
