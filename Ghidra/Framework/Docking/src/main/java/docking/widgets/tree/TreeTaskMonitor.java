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
package docking.widgets.tree;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;

/**
 * TaskMonitor implementation that is useful for monitor work when traversing trees.  
 * 
 * It works by subdividing the distance of the top-most progress bar (represented by the top-most
 * monitor) into equal size chunks depending on how many children have to be visited.  For example, 
 * assume the root node has 5 children, then the task bar for that node would increment 20% of
 * the bar as it completed work on each of its children. Now, assume each child of the root node 
 * has 10 children. The task monitor for each root child will operate entirely with its 20% as 
 * mentioned above.  So the first child of the first child will increment the progress bar 
 * 2% (10% of 20%) when it is complete.  
 */
public class TreeTaskMonitor implements TaskMonitor {
	// initialize to a huge number that can be subdivided many times
	private static long MAX_VALUE = 0x1000_0000_0000_0000L;
	private final TaskMonitor monitor;

	// This monitor operates on a sub-range of top-most monitor. The range min/max define that range
	private final long currentRangeMin;
	private final long currentRangeMax;

	// The amount of one increment increase the top-most monitor by this amount
	private long chunkSize;

	// These values are the max and progress for this sub-monitor
	private long max;
	private long progress;

	public TreeTaskMonitor(TaskMonitor monitor, long max) {
		if (monitor instanceof TreeTaskMonitor) {
			TreeTaskMonitor treeTaskMonitor = (TreeTaskMonitor) monitor;
			this.monitor = treeTaskMonitor.monitor;
			currentRangeMin = treeTaskMonitor.getTrueProgress();
			currentRangeMax = currentRangeMin + treeTaskMonitor.chunkSize;
		}
		else {
			this.monitor = monitor;
			currentRangeMin = 0;
			currentRangeMax = MAX_VALUE;
			monitor.initialize(MAX_VALUE);
		}
		setMaximum(max);
		progress = 0;
	}

	private long getTrueProgress() {
		return monitor.getProgress();
	}

	@Override
	public boolean isCancelled() {
		return monitor.isCancelled();
	}

	@Override
	public void setShowProgressValue(boolean showProgressValue) {
		monitor.setShowProgressValue(showProgressValue);
	}

	@Override
	public void setMessage(String message) {
		monitor.setMessage(message);
	}

	@Override
	public String getMessage() {
		return monitor.getMessage();
	}

	@Override
	public void setProgress(long value) {
		this.progress = value;
		monitor.setProgress(currentRangeMin + value * chunkSize);
	}

	@Override
	public void initialize(long maxValue) {
		setMaximum(maxValue);
	}

	@Override
	public void setMaximum(long maxValue) {
		if (maxValue > 0) {
			this.max = maxValue;

			// The size of the current window/section of the overall monitor 
			long currentRange = currentRangeMax - currentRangeMin;

			// the size of one increment within the current range
			chunkSize = Math.max(currentRange / max, 1);
		}
		else {
			this.max = 0;
			chunkSize = 0;
		}
	}

	@Override
	public long getMaximum() {
		return max;
	}

	@Override
	public void setIndeterminate(boolean indeterminate) {
		monitor.setIndeterminate(indeterminate);
	}

	@Override
	public boolean isIndeterminate() {
		return monitor.isIndeterminate();
	}

	@Override
	public void checkCanceled() throws CancelledException {
		monitor.checkCanceled();
	}

	@Override
	public void incrementProgress(long incrementAmount) {
		progress += incrementAmount;
		monitor.setProgress(currentRangeMin + progress * chunkSize);
	}

	@Override
	public long getProgress() {
		return progress;
	}

	@Override
	public void cancel() {
		monitor.cancel();
	}

	@Override
	public void addCancelledListener(CancelledListener listener) {
		monitor.addCancelledListener(listener);
	}

	@Override
	public void removeCancelledListener(CancelledListener listener) {
		monitor.removeCancelledListener(listener);
	}

	@Override
	public void setCancelEnabled(boolean enable) {
		monitor.setCancelEnabled(enable);
	}

	@Override
	public boolean isCancelEnabled() {
		return monitor.isCancelEnabled();
	}

	@Override
	public void clearCanceled() {
		monitor.clearCanceled();
	}
}
