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
package docking.widgets.table.threaded;

import static org.apache.commons.lang3.exception.ExceptionUtils.*;

import java.util.Collection;
import java.util.concurrent.CountDownLatch;

import javax.swing.SwingUtilities;

import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.SynchronizedListAccumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.SwingUpdateManager;
import ghidra.util.task.TaskMonitor;
import ghidra.util.worker.Job;

public class IncrementalLoadJob<ROW_OBJECT> extends Job implements ThreadedTableModelListener {
	private final IncrementalJobListener listener;
	private final ThreadedTableModel<ROW_OBJECT, ?> threadedModel;
	private final ThreadedTableModelUpdateMgr<ROW_OBJECT> updateManager;

	/** 
	 * Used to signal that the updateManager has finished loading the final contents gathered
	 * by this job.
	 */
	private final CountDownLatch completedCallbackLatch = new CountDownLatch(1);

	private volatile IncrementalUpdatingAccumulator incrementalAccumulator;

	IncrementalLoadJob(ThreadedTableModel<ROW_OBJECT, ?> threadedModel,
			IncrementalJobListener listener) {
		this.threadedModel = threadedModel;
		this.listener = listener;
		this.updateManager = threadedModel.getUpdateManager();
	}

	@Override
	public void run(TaskMonitor monitor) {

		// Do not create this in the constructor.  Some jobs never get started and thus are never
		// cancelled.  In that case, the accumulator's SwingUpdateManager never gets disposed.
		this.incrementalAccumulator = new IncrementalUpdatingAccumulator();

		notifyStarted(monitor);

		try {
			doExecute(monitor);
		}
		catch (Exception e) {

			// InterruptedException handled via notification below
			if (!hasCause(e, InterruptedException.class)) {
				// TODO: is there a better way to handle exceptions?  If we don't grab it and show
				// it here, then it will be handled by the Worker, which just prints it to the console.
				// Plus, handling it here gives us a chance to notify that the process is complete.
				String name = threadedModel.getName();
				Msg.showError(this, null, "Unexpected Exception",
					"Unexpected exception loading table model \"" + name + "\"", e);
			}
		}

		boolean interrupted = Thread.currentThread().isInterrupted();
		notifyCompleted(monitor.isCancelled() || interrupted);
	}

	private void doExecute(TaskMonitor monitor) {
		try {
			threadedModel.doLoad(incrementalAccumulator, monitor);
			if (!monitor.isCancelled()) { // in case the model didn't call checkCanceled()
				flush(incrementalAccumulator);
			}
		}
		catch (CancelledException e) {
			// handled by the caller of this method
		}

		if (monitor.isCancelled()) {
			return; // must leave now or we will block in the call below
		}

		waitForThreadedTableUpdateManager();
	}

	private void waitForThreadedTableUpdateManager() {
		try {
			completedCallbackLatch.await();
		}
		catch (InterruptedException e) {
			// This implies the user has cancelled the job by starting a new one or that we have
			// been disposed.  Whatever the cause, we want to let the control flow continue as 
			// normal.
			Thread.currentThread().interrupt(); // preserve the interrupt status
		}
	}

	private void flush(IncrementalUpdatingAccumulator accumulator) {
		//
		// Acquire the update manager lock so that it doesn't send out any events while we are
		// giving it the data we just finished loading.
		//
		synchronized (updateManager.getSynchronizingLock()) {
			// push the data to the update manager...
			accumulator.flushData();

			//
			// ...Add a listener to know when we can tell our listeners that loading is finished.
			//
			// (Add the listener later so that we don't get notified of any pending events from 
			// the update manager that may have already been posted by the time we have 
			// acquired the lock above.)
			//
			// Also, we are guaranteed that the flush() call will not call to the Swing thread
			// before we add our listener due to the fact that we currently hold a lock on the
			// updateManager, which is required to notify the listeners.  The basic sequence is:
			// 
			// -Flush starts a job thread (or uses the running one)
			// -We have the update manager's lock, so it blocks on jobDone() if that happens before
			//     this code can return
			// -We push the invokeLater()
			// -We release the lock
			// -A block on jobDone() can now complete as we release the lock
			// -jobDone() will notify listeners in an invokeLater(), which puts it behind ours
			//
			SwingUtilities.invokeLater(
				() -> updateManager.addThreadedTableListener(IncrementalLoadJob.this));
		}
	}

	private void notifyStarted(TaskMonitor monitor) {
		if (listener != null) {
			SystemUtilities.runIfSwingOrPostSwingLater(() -> listener.loadingStarted());
		}
	}

	private void notifyCompleted(final boolean wasCancelled) {
		if (listener != null) {
			SystemUtilities.runIfSwingOrPostSwingLater(
				() -> listener.loadingFinished(wasCancelled));
		}

		updateManager.removeThreadedTableListener(this);

	}

	@Override
	public void cancel() {
		updateManager.getTaskMonitor().cancel();
		// monitor.cancel();  TODO: are we handling this ??
		incrementalAccumulator.cancel();
	}

	@Override
	public void loadPending() {
		// we've already notified start
	}

	@Override
	public void loadingStarted() {
		// we've already notified start
	}

	@Override
	public void loadingFinished(boolean wasCancelled) {
		// At this point we are in a normal completed callback from the update manager.  This
		// is when we need the latch to be counted down.  In the abnormal failure/cancel case, 
		// we will not block on the latch and thus it doesn't need to be counted down elsewhere.
		completedCallbackLatch.countDown();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	/**
	 * An accumulator that will essentially periodically update the table with the data that 
	 * is being provided to the accumulator.
	 */
	private class IncrementalUpdatingAccumulator extends SynchronizedListAccumulator<ROW_OBJECT> {
		private volatile boolean cancelledOrDone;
		private Runnable runnable = () -> {
			if (cancelledOrDone) {
				// this handles the case where a cancel request came in off the Swing
				// thread whilst we were already posted
				return;
			}
			updateManager.reloadSpecificData(asList());
		};

		private SwingUpdateManager swingUpdateManager =
			new SwingUpdateManager((int) threadedModel.getMinDelay(),
				(int) threadedModel.getMaxDelay(), "Incremental Table Load Update", runnable);

		@Override
		public synchronized void add(ROW_OBJECT t) {
			super.add(t);
			swingUpdateManager.update();
		}

		void cancel() {
			cancelledOrDone = true;
			swingUpdateManager.dispose();
		}

		@Override
		public synchronized void addAll(Collection<ROW_OBJECT> collection) {
			super.addAll(collection);
			if (collection.size() > 0) {
				swingUpdateManager.update();
			}
		}

		void flushData() {
			cancelledOrDone = true;
			swingUpdateManager.dispose();
			updateManager.reloadSpecificData(asList());
		}
	}
}
