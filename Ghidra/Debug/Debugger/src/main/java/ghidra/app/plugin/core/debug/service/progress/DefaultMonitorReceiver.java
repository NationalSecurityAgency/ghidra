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

import ghidra.debug.api.progress.MonitorReceiver;
import ghidra.debug.api.progress.ProgressListener.Disposal;
import ghidra.util.datastruct.ListenerSet;
import ghidra.util.task.CancelledListener;

public class DefaultMonitorReceiver implements MonitorReceiver {
	private final ProgressServicePlugin plugin;
	private final ListenerSet<CancelledListener> listeners =
		new ListenerSet<>(CancelledListener.class, true);
	private final Object lock = new Object();

	private boolean cancelled = false;
	private boolean indeterminate = false;
	private boolean cancelEnabled = true;
	private boolean showProgressValue = true;

	private boolean valid = true;

	private String message = "";
	private long maximum;
	private long progress;

	public DefaultMonitorReceiver(ProgressServicePlugin plugin) {
		this.plugin = plugin;
	}

	@Override
	public boolean isCancelled() {
		return cancelled;
	}

	@Override
	public void cancel() {
		synchronized (lock) {
			if (this.cancelled == true) {
				return;
			}
			this.cancelled = true;
		}
		listeners.invoke().cancelled();
		plugin.listeners.invoke().attributeUpdated(this);
	}

	void setShowProgressValue(boolean showProgressValue) {
		synchronized (lock) {
			if (this.showProgressValue == showProgressValue) {
				return;
			}
			this.showProgressValue = showProgressValue;
		}
		plugin.listeners.invoke().attributeUpdated(this);
	}

	void setMessage(String message) {
		synchronized (lock) {
			if (message == null) {
				this.message = "";
			}
			else {
				this.message = message;
			}
		}
		plugin.listeners.invoke().messageUpdated(this, this.message);
	}

	void reportError(Throwable error) {
		plugin.listeners.invoke().errorReported(this, error);
	}

	@Override
	public String getMessage() {
		synchronized (lock) {
			return message;
		}
	}

	void setProgress(long progress) {
		synchronized (lock) {
			this.progress = progress;
		}
		plugin.listeners.invoke().progressUpdated(this, progress);
	}

	void incrementProgress(long amount) {
		long progress;
		synchronized (lock) {
			progress = this.progress + amount;
			this.progress = progress;
		}
		plugin.listeners.invoke().progressUpdated(this, progress);
	}

	@Override
	public long getProgress() {
		return progress;
	}

	void setMaximum(long maximum) {
		synchronized (lock) {
			if (this.maximum == maximum) {
				return;
			}
			this.maximum = maximum;
		}
		plugin.listeners.invoke().attributeUpdated(this);
	}

	@Override
	public long getMaximum() {
		synchronized (lock) {
			return maximum;
		}
	}

	void setIndeterminate(boolean indeterminate) {
		synchronized (lock) {
			if (this.indeterminate == indeterminate) {
				return;
			}
			this.indeterminate = indeterminate;
		}
		plugin.listeners.invoke().attributeUpdated(this);
	}

	@Override
	public boolean isIndeterminate() {
		return indeterminate;
	}

	void addCancelledListener(CancelledListener listener) {
		listeners.add(listener);
	}

	void removeCancelledListener(CancelledListener listener) {
		listeners.remove(listener);
	}

	void setCancelEnabled(boolean cancelEnabled) {
		synchronized (lock) {
			if (this.cancelEnabled == cancelEnabled) {
				return;
			}
			this.cancelEnabled = cancelEnabled;
		}
		plugin.listeners.invoke().attributeUpdated(this);
	}

	@Override
	public boolean isCancelEnabled() {
		return cancelEnabled;
	}

	@Override
	public boolean isShowProgressValue() {
		return showProgressValue;
	}

	public void close() {
		synchronized (lock) {
			if (!this.valid) {
				return;
			}
			this.valid = false;
		}
		plugin.disposeMonitor(this, Disposal.CLOSED);
	}

	public void clean() {
		synchronized (lock) {
			if (!this.valid) {
				return;
			}
			this.valid = false;
		}
		plugin.disposeMonitor(this, Disposal.CLEANED);
	}

	@Override
	public boolean isValid() {
		return this.valid;
	}
}
