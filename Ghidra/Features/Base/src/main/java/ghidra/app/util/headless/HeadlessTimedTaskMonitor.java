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
package ghidra.app.util.headless;

import java.util.Timer;
import java.util.TimerTask;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;

/**
 * Monitor used by Headless Analyzer for "timeout" functionality
 */
public class HeadlessTimedTaskMonitor implements TaskMonitor {

	private Timer timer = new Timer();
	private volatile boolean isCancelled;

	HeadlessTimedTaskMonitor(int timeoutSecs) {
		isCancelled = false;
		timer.schedule(new TimeOutTask(), timeoutSecs * 1000);
	}

	private class TimeOutTask extends TimerTask {
		@Override
		public void run() {
			HeadlessTimedTaskMonitor.this.cancel();
		}
	}

	@Override
	public boolean isCancelled() {
		return isCancelled;
	}

	@Override
	public void setShowProgressValue(boolean showProgressValue) {
		// stub
	}

	@Override
	public void setMessage(String message) {
		// stub
	}

	@Override
	public String getMessage() {
		return null;
	}

	@Override
	public void setProgress(long value) {
		// stub
	}

	@Override
	public void initialize(long max) {
		// stub
	}

	@Override
	public void setMaximum(long max) {
		// stub
	}

	@Override
	public long getMaximum() {
		return 0;
	}

	@Override
	public void setIndeterminate(boolean indeterminate) {
		// stub
	}

	@Override
	public boolean isIndeterminate() {
		return false;
	}

	@Override
	public void checkCanceled() throws CancelledException {
		if (isCancelled()) {
			throw new CancelledException();
		}
	}

	@Override
	public void incrementProgress(long incrementAmount) {
		// stub
	}

	@Override
	public long getProgress() {
		return 0;
	}

	@Override
	public void cancel() {
		timer.cancel(); // Terminate the timer thread
		isCancelled = true;
	}

	@Override
	public void addCancelledListener(CancelledListener listener) {
		// stub
	}

	@Override
	public void removeCancelledListener(CancelledListener listener) {
		// stub
	}

	@Override
	public void setCancelEnabled(boolean enable) {
		// stub
	}

	@Override
	public boolean isCancelEnabled() {
		return true;
	}

	@Override
	public void clearCanceled() {
		isCancelled = false;
	}
}
