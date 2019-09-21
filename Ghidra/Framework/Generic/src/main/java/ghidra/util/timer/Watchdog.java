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
package ghidra.util.timer;

import java.io.Closeable;
import java.util.concurrent.atomic.AtomicLong;

import ghidra.util.Msg;

/**
 * A reusable watchdog that will execute a callback if the watchdog is not disarmed before
 * it expires.
 *
 */
public class Watchdog implements Closeable {
	private long defaultWatchdogTimeoutMS;
	private AtomicLong watchdogExpiresAt = new AtomicLong();
	private Runnable timeoutMethod;
	private GTimerMonitor watchdogTimer;

	/**
	 * Creates a watchdog (initially disarmed) that will poll for expiration every
	 * defaultTimeoutMS milliseconds, calling {@code timeoutMethod} when triggered.
	 * <p>
	 * @param defaultTimeoutMS number of milliseconds that the watchdog will wait after
	 * being armed before calling the timeout method.
	 * @param timeoutMethod {@link Runnable} functional callback.
	 */
	public Watchdog(long defaultTimeoutMS, Runnable timeoutMethod) {
		this.defaultWatchdogTimeoutMS = defaultTimeoutMS;
		this.timeoutMethod = timeoutMethod;
		this.watchdogTimer = GTimer.scheduleRepeatingRunnable(defaultTimeoutMS, defaultTimeoutMS,
			this::watchdogWorker);
	}

	@Override
	public void finalize() {
		if (watchdogTimer != null) {
			close();
			Msg.warn(this, "Unclosed Watchdog");
		}
	}

	/**
	 * Releases the background timer that this watchdog uses.
	 */
	@Override
	public void close() {
		if (watchdogTimer != null) {
			watchdogTimer.cancel();
		}
		watchdogTimer = null;
		timeoutMethod = null;
	}

	/**
	 * Called from a timer, checks to see if the watchdog is armed, and if it has expired.
	 * <p>
	 * Disarms itself before calling the timeoutMethod if the timeout period expired.
	 */
	private void watchdogWorker() {
		long expiresAt = watchdogExpiresAt.get();
		if (expiresAt > 0) {
			long now = System.currentTimeMillis();
			if (now > expiresAt) {
				setEnabled(false);
				timeoutMethod.run();
			}
		}

	}

	private void setEnabled(boolean b) {
		watchdogExpiresAt.set(b ? System.currentTimeMillis() + defaultWatchdogTimeoutMS : -1);
	}

	/**
	 * Returns the status of the watchdog.
	 *
	 * @return true if the watchdog is armed, false if the watchdog is disarmed
	 */
	public boolean isEnabled() {
		return watchdogExpiresAt.get() > 0;
	}

	/**
	 * Enables this watchdog so that at {@link #defaultWatchdogTimeoutMS} milliseconds in the
	 * future the {@link #timeoutMethod} will be called.
	 */
	public void arm() {
		setEnabled(true);
	}

	/**
	 * Disables this watchdog.
	 */
	public void disarm() {
		setEnabled(false);
	}

}
