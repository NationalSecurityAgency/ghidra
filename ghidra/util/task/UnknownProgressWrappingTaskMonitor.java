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

import ghidra.util.exception.CancelledException;

/**
 * A class that is meant to wrap a {@link TaskMonitor} when you do not know the maximum value
 * of the progress.
 */
public class UnknownProgressWrappingTaskMonitor extends TaskMonitorAdapter {

	private TaskMonitor delegate;

	public UnknownProgressWrappingTaskMonitor(TaskMonitor delegate, long startMaximum) {
		this.delegate = delegate;
		delegate.setMaximum(startMaximum);
	}

	@Override
	public void setMessage(String message) {
		delegate.setMessage(message);
	}

	@Override
	public void setProgress(long value) {
		delegate.setProgress(value);
		maybeUpdateMaximum();
	}

	@Override
	public void incrementProgress(long incrementAmount) {
		delegate.incrementProgress(incrementAmount);
		maybeUpdateMaximum();
	}

	@Override
	public synchronized boolean isCancelled() {
		return delegate.isCancelled();
	}

	@Override
	public void checkCanceled() throws CancelledException {
		delegate.checkCanceled();
	}

	private void maybeUpdateMaximum() {
		long currentMaximum = delegate.getMaximum();
		long progress = delegate.getProgress();

		int _75_percent = (int) (currentMaximum * .75);
		if (progress > _75_percent) {
			delegate.setMaximum(currentMaximum + (currentMaximum - _75_percent));
		}
	}

}
