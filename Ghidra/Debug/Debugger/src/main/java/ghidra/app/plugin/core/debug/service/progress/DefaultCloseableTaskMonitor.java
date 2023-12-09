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
package ghidra.app.plugin.core.debug.service.progress;

import java.lang.ref.Cleaner;

import javax.help.UnsupportedOperationException;

import ghidra.debug.api.progress.CloseableTaskMonitor;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.CancelledListener;

public class DefaultCloseableTaskMonitor implements CloseableTaskMonitor {
	private static final Cleaner CLEANER = Cleaner.create();

	static class State implements Runnable {
		private final DefaultMonitorReceiver receiver;

		State(DefaultMonitorReceiver receiver) {
			this.receiver = receiver;
		}

		@Override
		public void run() {
			receiver.clean();
		}
	}

	private final DefaultMonitorReceiver receiver;
	private final State state;
	@SuppressWarnings("unused")
	private final Cleaner.Cleanable cleanable;

	public DefaultCloseableTaskMonitor(ProgressServicePlugin plugin) {
		this.receiver = new DefaultMonitorReceiver(plugin);
		this.state = new State(receiver);
		this.cleanable = CLEANER.register(this, state);
	}

	DefaultMonitorReceiver getReceiver() {
		return receiver;
	}

	@Override
	public boolean isCancelled() {
		return receiver.isCancelled();
	}

	@Override
	public void setShowProgressValue(boolean showProgressValue) {
		receiver.setShowProgressValue(showProgressValue);
	}

	@Override
	public void setMessage(String message) {
		receiver.setMessage(message);
	}

	@Override
	public String getMessage() {
		return receiver.getMessage();
	}

	@Override
	public void setProgress(long value) {
		receiver.setProgress(value);
	}

	@Override
	public void initialize(long max) {
		receiver.setProgress(0);
		receiver.setMaximum(max);
	}

	@Override
	public void setMaximum(long max) {
		receiver.setMaximum(max);
	}

	@Override
	public long getMaximum() {
		return receiver.getMaximum();
	}

	@Override
	public void setIndeterminate(boolean indeterminate) {
		receiver.setIndeterminate(indeterminate);
	}

	@Override
	public boolean isIndeterminate() {
		return receiver.isIndeterminate();
	}

	@Override
	public void checkCanceled() throws CancelledException {
		if (receiver.isCancelled()) {
			throw new CancelledException();
		}
	}

	@Override
	public void incrementProgress(long incrementAmount) {
		receiver.incrementProgress(incrementAmount);
	}

	@Override
	public long getProgress() {
		return receiver.getProgress();
	}

	@Override
	public void cancel() {
		receiver.cancel();
	}

	@Override
	public void addCancelledListener(CancelledListener listener) {
		receiver.addCancelledListener(listener);
	}

	@Override
	public void removeCancelledListener(CancelledListener listener) {
		receiver.removeCancelledListener(listener);
	}

	@Override
	public void setCancelEnabled(boolean enable) {
		receiver.setCancelEnabled(enable);
	}

	@Override
	public boolean isCancelEnabled() {
		return receiver.isCancelEnabled();
	}

	@Override
	public void clearCanceled() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void close() {
		receiver.close();
	}
}
