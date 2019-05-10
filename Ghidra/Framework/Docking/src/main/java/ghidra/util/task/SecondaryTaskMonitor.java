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

import ghidra.util.exception.CancelledException;

/**
 * {@link TaskMonitor} that restricts users from being able to update the progress bar. The class 
 * is initialized with another, fully-featured monitor and forwards all requests to it,
 * but squashes calls to methods that are not allowed. 
 * <p>
 * Note: Two instances of this class are deemed equal if they have the same {@link #parentMonitor},
 * hence the override of {@link #hashCode()} and {@link #equals(Object)}.
 */
public class SecondaryTaskMonitor implements TaskMonitor {
	
	private TaskMonitor parentMonitor;

	/**
	 * Constructor
	 * 
	 * @param parentMonitor the fully-functional task monitor this is based off of
	 */
	public SecondaryTaskMonitor(TaskMonitor parentMonitor) {
		this.parentMonitor = parentMonitor;
	}

	/**
	 * Overridden to ensure that clients who have this type of monitor will only update the
	 * secondary message when using this method
	 * 
	 * @param message the message string to display
	 */
	@Override
	public void setMessage(String message) {
		if (parentMonitor instanceof TaskDialog) {
			((TaskDialog) parentMonitor).setSecondaryMessage(message);
			return;
		}
		parentMonitor.setMessage(message);
	}

	@Override
	public void setCancelEnabled(boolean enable) {
		parentMonitor.setCancelEnabled(enable);
	}

	@Override
	public void setInitialized(boolean init) {
		parentMonitor.setInitialized(init);
	}

	/**
	 * Secondary monitors should not be able to reset progress or revert back
	 * to an uninitialized state; hence the override.
	 */
	@Override
	public void finished() {
		synchronized (this) {
			setMessage("");
		}
	}

	@Override
	public boolean isCancelEnabled() {
		return parentMonitor.isCancelEnabled();
	}

	@Override
	public boolean isCancelled() {
		return parentMonitor.isCancelled();
	}

	@Override
	public synchronized void cancel() {
		parentMonitor.cancel();
	}

	@Override
	public synchronized void clearCanceled() {
		parentMonitor.clearCanceled();
	}

	@Override
	public void checkCanceled() throws CancelledException {
		parentMonitor.checkCanceled();
	}

	@Override
	public void addCancelledListener(CancelledListener listener) {
		parentMonitor.addCancelledListener(listener);
	}

	@Override
	public void removeCancelledListener(CancelledListener listener) {
		parentMonitor.removeCancelledListener(listener);
	}

	@Override
	public long getMaximum() {
		return parentMonitor.getMaximum();
	}

	@Override
	public long getProgress() {
		return parentMonitor.getProgress();
	}

	@Override
	public void setShowProgressValue(boolean showProgressValue) {
		// squash
	}

	@Override
	public void setProgress(long value) {
		// squash
	}

	@Override
	public void initialize(long max) {
		// squash
	}

	@Override
	public void setMaximum(long max) {
		// squash
	}

	@Override
	public void setIndeterminate(boolean indeterminate) {
		// squash
	}

	@Override
	public void incrementProgress(long incrementAmount) {
		// squash
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((parentMonitor == null) ? 0 : parentMonitor.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		SecondaryTaskMonitor other = (SecondaryTaskMonitor) obj;
		if (!Objects.equals(parentMonitor, other.parentMonitor)) {
			return false;
		}

		return true;
	}
}
