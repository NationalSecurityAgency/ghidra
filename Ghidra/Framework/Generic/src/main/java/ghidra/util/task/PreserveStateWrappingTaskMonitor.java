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

import java.io.Closeable;

/**
 * A {@link TaskMonitor} wrapper that restores all changed values of the wrapped TaskMonitor when
 * the wrapper is {@link #close() closed}.
 */
public class PreserveStateWrappingTaskMonitor extends WrappingTaskMonitor implements Closeable {

	private Boolean origCancelEnabled;
	private Boolean origIndeterminate;
	private Boolean origShowProgress;
	private String origMessage;
	private Long origMax;
	private Long origProgress;

	public PreserveStateWrappingTaskMonitor(TaskMonitor delegate) {
		super(delegate);
	}

	@Override
	public void close() {
		if (origCancelEnabled != null) {
			super.setCancelEnabled(origCancelEnabled);
		}
		if (origIndeterminate != null) {
			super.setIndeterminate(origIndeterminate);
		}
		if (origShowProgress != null) {
			super.setShowProgressValue(origShowProgress);
		}
		if (origMessage != null) {
			super.setMessage(origMessage);
		}
		if (origMax != null) {
			super.setMaximum(origMax);
		}
		if (origProgress != null) {
			super.setProgress(origProgress);
		}
	}

	@Override
	public synchronized void setCancelEnabled(boolean enable) {
		if (origCancelEnabled == null) {
			origCancelEnabled = isCancelEnabled();
		}
		super.setCancelEnabled(enable);
	}

	@Override
	public synchronized void setIndeterminate(boolean indeterminate) {
		if (origIndeterminate == null) {
			origIndeterminate = isIndeterminate();
		}
		super.setIndeterminate(indeterminate);
	}

	@Override
	public void setShowProgressValue(boolean showProgressValue) {
		if (origShowProgress == null) {
			origShowProgress = true; // there is no isShowProgress() that we can call
		}
		super.setShowProgressValue(showProgressValue);
	}

	@Override
	public void setMessage(String message) {
		if (origMessage == null) {
			origMessage = getMessage();
		}
		super.setMessage(message);
	}

	@Override
	public synchronized void setMaximum(long max) {
		if (origMax == null) {
			origMax = super.getMaximum();
		}
		super.setMaximum(max);
	}

	@Override
	public void setProgress(long value) {
		if (origProgress == null) {
			origProgress = super.getProgress();
		}
		super.setProgress(value);
	}

	@Override
	public void incrementProgress(long incrementAmount) {
		if (origProgress == null) {
			origProgress = super.getProgress();
		}
		super.incrementProgress(incrementAmount);
	}
}
