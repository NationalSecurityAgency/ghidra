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
package generic.timer;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;

/**
 * This class allows clients to run swing action at some point in the future, when the given 
 * condition is met, allowing for the task to timeout.  While this class implements the
 * {@link GhidraTimer} interface, it is really meant to be used to execute a code snippet one
 * time at some point in the future.  
 * 
 * <p>Both the call to check for readiness and the actual client code will be run on the Swing
 * thread.
 */
public class ExpiringSwingTimer extends GhidraSwingTimer {

	private long startMs = System.currentTimeMillis();
	private int expireMs;
	private BooleanSupplier isReady;
	private ExpiringTimerCallback expiringTimerCallback = new ExpiringTimerCallback();
	private TimerCallback clientCallback;
	private AtomicBoolean didRun = new AtomicBoolean();

	/**
	 * Runs the given client runnable when the given condition returns true.  The returned timer 
	 * will be running.
	 * 
	 * <p>Once the timer has performed the work, any calls to start the returned timer will 
	 * not perform any work.  You can check {@link #didRun()} to see if the work has been completed.
	 * 
	 * @param isReady true if the code should be run
	 * @param expireMs the amount of time past which the code will not be run
	 * @param runnable the code to run
	 * @return the timer object that is running, which will execute the given code when ready
	 */
	public static ExpiringSwingTimer runWhen(BooleanSupplier isReady,
			int expireMs,
			Runnable runnable) {

		// Note: we could let the client specify the period, but that would add an extra argument
		//       to this method. For now, just use something reasonable.
		int delay = 250;
		ExpiringSwingTimer timer =
			new ExpiringSwingTimer(delay, expireMs, isReady, runnable);
		timer.start();
		return timer;
	}

	/**
	 * Constructor
	 * 
	 * <p>Note: this class sets the parent's initial delay to 0.  This is to allow the client 
	 * code to be executed without delay when the ready condition is true.
	 * 
	 * @param delay the delay between calls to check <code>isReady</code>
	 * @param isReady true if the code should be run
	 * @param expireMs the amount of time past which the code will not be run
	 * @param runnable the code to run
	 */
	public ExpiringSwingTimer(int delay, int expireMs, BooleanSupplier isReady,
			Runnable runnable) {
		super(0, delay, null);
		this.expireMs = expireMs;
		this.isReady = isReady;
		this.clientCallback = () -> runnable.run();
		super.setTimerCallback(expiringTimerCallback);
		setRepeats(true);
	}

	/**
	 * Returns true if the client runnable was run 
	 * @return true if the client runnable was run
	 */
	public boolean didRun() {
		return didRun.get();
	}

	@Override
	public void start() {
		if (didRun() || isExpired()) {
			return;
		}

		super.start();
	}

	/**
	 * Returns true the initial expiration period has passed
	 * @return true if expired
	 */
	public boolean isExpired() {
		long now = System.currentTimeMillis();
		int elapsed = (int) (now - startMs);
		return elapsed > expireMs;
	}

	@Override
	public void setTimerCallback(TimerCallback callback) {
		// overridden to ensure clients cannot overwrite out wrapping callback
		this.clientCallback = Objects.requireNonNull(callback);
	}

	private class ExpiringTimerCallback implements TimerCallback {

		@Override
		public void timerFired() {

			if (isReady.getAsBoolean()) {
				clientCallback.timerFired();
				didRun.set(true);
				stop();
				return;
			}
			else if (isExpired()) {
				stop();
			}
		}
	}
}
