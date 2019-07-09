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

import java.util.HashSet;
import java.util.Set;

import generic.concurrent.ConcurrentListenerSet;
import ghidra.util.exception.CancelledException;

public class TaskMonitorSplitter {
	public static int MONITOR_SIZE = 100000;

	public static TaskMonitor[] splitTaskMonitor(TaskMonitor monitor, int n) {
		TaskMonitor[] subMonitors = new TaskMonitor[n];
		monitor.initialize(MONITOR_SIZE);
		double subSize = (double) MONITOR_SIZE / n;
		Set<SubTaskMonitor> sharedSet = new HashSet<>();
		for (int i = 0; i < n; i++) {
			subMonitors[i] = new SubTaskMonitor(monitor, subSize, sharedSet);
		}
		return subMonitors;
	}

	static class SubTaskMonitor implements TaskMonitor, CancelledListener {
		private long max = 100;
		private long progress = 0;
		private TaskMonitor parent;
		private ConcurrentListenerSet<CancelledListener> listeners;
		private int parentProgress;
		private double subSize;

		public SubTaskMonitor(TaskMonitor parent, double subSize,
				Set<SubTaskMonitor> notDoneYetSet) {
			this.parent = parent;
			this.subSize = subSize;
			notDoneYetSet.add(this);
			parent.addCancelledListener(this);
		}

		@Override
		public void addCancelledListener(CancelledListener listener) {
			if (listeners == null) {
				listeners = new ConcurrentListenerSet<>();
			}
			listeners.add(listener);
		}

		@Override
		public void cancel() {
			parent.cancel();
		}

		@Override
		public void checkCanceled() throws CancelledException {
			parent.checkCanceled();
		}

		@Override
		public void clearCanceled() {
			throw new UnsupportedOperationException();
		}

		@Override
		public long getMaximum() {
			return max;
		}

		@Override
		public long getProgress() {
			return progress;
		}

		@Override
		public void incrementProgress(long incrementAmount) {
			progress += incrementAmount;
			normalizeProgress();

			updateParent();
		}

		private void updateParent() {
			int newParentProgress = max == 0 ? 0 : (int) ((progress * subSize) / max);
			parent.incrementProgress(newParentProgress - parentProgress);
			parentProgress = newParentProgress;
		}

		private void normalizeProgress() {
			if (progress > max) {
				progress = max;
			}
		}

		@Override
		public boolean isCancelEnabled() {
			return parent.isCancelEnabled();
		}

		@Override
		public boolean isCancelled() {
			return parent.isCancelled();
		}

		@Override
		public void removeCancelledListener(CancelledListener listener) {
			if (listeners != null) {
				listeners.remove(listener);
			}
		}

		@Override
		public void setCancelEnabled(boolean enable) {
			parent.setCancelEnabled(enable);
		}

		@Override
		public void setShowProgressValue(boolean showProgressValue) {
			parent.setShowProgressValue(showProgressValue);
		}

		@Override
		public void setIndeterminate(boolean indeterminate) {
			parent.setIndeterminate(indeterminate);
		}

		@Override
		public boolean isIndeterminate() {
			return parent.isIndeterminate();
		}

		@Override
		public void initialize(long newMax) {
			setMaximum(newMax);
			setProgress(0);
		}

		@Override
		public void setMaximum(long newMax) {
			this.max = newMax;
			normalizeProgress();
			updateParent();
		}

		@Override
		public void setMessage(String message) {
			parent.setMessage(message);
		}

		@Override
		public String getMessage() {
			return parent.getMessage();
		}

		@Override
		public void setProgress(long value) {
			progress = value;
			normalizeProgress();
			updateParent();
		}

		@Override
		public void cancelled() {
			notifyListeners();
		}

		private void notifyListeners() {
			if (listeners == null) {
				return;
			}
			for (CancelledListener listener : listeners) {
				listener.cancelled();
			}
		}
	}
}
