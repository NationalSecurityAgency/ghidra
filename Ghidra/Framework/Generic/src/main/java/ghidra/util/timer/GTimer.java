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

import java.util.Timer;
import java.util.TimerTask;

import ghidra.util.Msg;

/**
 * A class to schedule {@link Runnable}s to run after some delay, optionally repeating.  This class
 * uses a {@link Timer} internally to schedule work.   Clients of this class are given a monitor
 * that allows them to check on the state of the runnable, as well as to cancel the runnable.
 */
public class GTimer {
	private static Timer timer;
	private static GTimerMonitor DO_NOTHING_MONITOR = GTimerMonitor.DUMMY;

	/**
	 * Schedules a runnable for execution after the specified delay.   A delay value less than 0
	 * will cause this timer to schedule nothing.  This allows clients to use this timer class
	 * with no added logic for managing timer enablement.
	 *
	 * @param delay the time (in milliseconds) to wait before executing the runnable.  A negative
	 *        value signals not to run the timer--the callback will not be executed
	 * @param callback the runnable to be executed.
	 * @return a GTimerMonitor which allows the caller to cancel the timer and check its status.
	 */
	public static GTimerMonitor scheduleRunnable(long delay, Runnable callback) {
		if (delay < 0) {
			return DO_NOTHING_MONITOR;
		}
		GTimerTask gTimerTask = new GTimerTask(callback);
		getTimer().schedule(gTimerTask, delay);
		return gTimerTask;
	}

	/**
	 * Schedules a runnable for <b>repeated</b> execution after the specified delay. A delay value
	 * less than 0 will cause this timer to schedule nothing.  This allows clients to use this
	 * timer class with no added logic for managing timer enablement.
	 *
	 * @param delay the time (in milliseconds) to wait before executing the runnable.   A negative
	 *        value signals not to run the timer--the callback will not be executed
	 * @param period time in milliseconds between successive runnable executions
	 * @param callback the runnable to be executed
	 * @return a GTimerMonitor which allows the caller to cancel the timer and check its status
	 * @throws IllegalArgumentException if {@code period <= 0}
	 */
	public static GTimerMonitor scheduleRepeatingRunnable(long delay, long period,
			Runnable callback) {
		if (delay < 0) {
			return DO_NOTHING_MONITOR;
		}
		GTimerTask gTimerTask = new GTimerTask(callback);
		getTimer().schedule(gTimerTask, delay, period);
		return gTimerTask;
	}

	private static synchronized Timer getTimer() {
		if (timer == null) {
			timer = new Timer("GTimer", true);
		}
		return timer;
	}

	static class GTimerTask extends TimerTask implements GTimerMonitor {

		private final Runnable runnable;
		private boolean wasCancelled;
		private boolean wasRun;

		GTimerTask(Runnable runnable) {
			this.runnable = runnable;
		}

		@Override
		public void run() {
			try {
				runnable.run();
				wasRun = true;
			}
			catch (Throwable t) {
				Msg.showError(this, null, "Unexpected Exception",
					"Unexpected exception running timer task", t);
			}
		}

		@Override
		public boolean didRun() {
			return wasRun;
		}

		@Override
		public boolean wasCancelled() {
			return wasCancelled;
		}

		@Override
		public boolean cancel() {
			wasCancelled = super.cancel();
			return wasCancelled;
		}

	}
}
