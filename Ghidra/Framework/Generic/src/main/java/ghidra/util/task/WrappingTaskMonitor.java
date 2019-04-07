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

import ghidra.util.Issue;
import ghidra.util.exception.CancelledException;

/**
 * An implementation of the {@link TaskMonitor} interface that simply wraps a delegate task
 * monitor.   This is useful for classes that wish to wrap a task monitor, changing behavior
 * as needed by overriding a subset of methods.
 */
public class WrappingTaskMonitor implements TaskMonitor {

	protected final TaskMonitor delegate;

	/**
	 * Constructor
	 * 
	 * @param delegate the delegate task monitor
	 */
	public WrappingTaskMonitor(TaskMonitor delegate) {
		this.delegate = delegate;
	}

	@Override
	public boolean isCancelled() {
		return delegate.isCancelled();
	}

	@Override
	public void setShowProgressValue(boolean showProgressValue) {
		delegate.setShowProgressValue(showProgressValue);
	}

	@Override
	public void setMessage(String message) {
		delegate.setMessage(message);
	}

	@Override
	public void setProgress(long value) {
		delegate.setProgress(value);
	}

	@Override
	public void initialize(long max) {
		delegate.initialize(max);
	}

	@Override
	public void setMaximum(long max) {
		delegate.setMaximum(max);
	}

	@Override
	public long getMaximum() {
		return delegate.getMaximum();
	}

	@Override
	public void setIndeterminate(boolean indeterminate) {
		delegate.setIndeterminate(indeterminate);
	}

	@Override
	public void checkCanceled() throws CancelledException {
		delegate.checkCanceled();
	}

	@Override
	public void incrementProgress(long incrementAmount) {
		delegate.incrementProgress(incrementAmount);
	}

	@Override
	public long getProgress() {
		return delegate.getProgress();
	}

	@Override
	public void reportIssue(Issue issue) {
		delegate.reportIssue(issue);
	}

	@Override
	public void cancel() {
		delegate.cancel();
	}

	@Override
	public void addCancelledListener(CancelledListener listener) {
		delegate.addCancelledListener(listener);
	}

	@Override
	public void removeCancelledListener(CancelledListener listener) {
		delegate.removeCancelledListener(listener);
	}

	@Override
	public void setCancelEnabled(boolean enable) {
		delegate.setCancelEnabled(enable);
	}

	@Override
	public boolean isCancelEnabled() {
		return delegate.isCancelEnabled();
	}

	@Override
	public void clearCanceled() {
		delegate.clearCanceled();
	}

	@Override
	public void addIssueListener(IssueListener listener) {
		delegate.addIssueListener(listener);
	}

	@Override
	public void removeIssueListener(IssueListener listener) {
		delegate.removeIssueListener(listener);
	}
}
