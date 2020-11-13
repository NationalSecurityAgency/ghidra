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

import ghidra.util.exception.AssertException;

import java.util.Timer;
import java.util.TimerTask;

/**
 * The GhidraSwinglessTimer is similar to the javax.swing.Timer class.  The big difference is
 * that it does NOT use the swing thread for its callbacks.  Similar to the swing timer, only 
 * one timer thread is ever used no matter how many GhidraSwinglessTimers are instantiated.
 * 
 * It fires one or more {@code TimerCallback}s at specified
 * intervals. 
 * Setting up a timer
 * involves creating a <code>GhidraSwinglessTimer</code> object,
 * registering one or more TimerCallbacks on it,
 * and starting the timer using
 * the <code>start</code> method.
 *
 */
public class GhidraSwinglessTimer implements GhidraTimer {
	private static final long CLEANUP_TIMER_THREAD_DELAY = 60000;
	private static Timer timer;
	private static int taskCount = 0;
	private static CleanupTimerTask cleanupTask = null;
	
	private static synchronized Timer getTimer() {
		if (timer == null) {
			timer = new Timer("GhidraSwinglessTimer", true);
		}
		return timer;
	}

	private static synchronized void incrementCount() {
		taskCount++;
		if (cleanupTask != null) {
			cleanupTask.cancel();
			cleanupTask = null;
		}
	}

	private static synchronized void decrementCount() {
		taskCount--;
		if (taskCount < 0) {
			throw new AssertException("Timer count out of sync.");
		}
		if (taskCount == 0) {
			cleanupTask = new CleanupTimerTask();
			getTimer().schedule(cleanupTask, CLEANUP_TIMER_THREAD_DELAY);	
		}
	}

	private static synchronized void cleanupTimer() {
		cleanupTask = null;
		if (taskCount == 0) {
			timer.cancel();
			timer = null;
		}
	}
	
	
	private TimerCallback callback;
	private boolean repeats;
	private int delay;
	private int initialDelay;
	private TimerTask timerTask;

	/**
	 * Creates a new repeating timer with a initial delay of 100ms and a continual delay of 100ms. 
	 */
	public GhidraSwinglessTimer() {
		this(100, null);
	}
	
	/**
	 * Creates a new repeating timer with a initial and continual delay with the given delay. 
	 * @param delay the delay to use for the first and subsequent timer callbacks.
	 * @param callback the callback the be called with the timer fires.
	 */
	public GhidraSwinglessTimer(int delay, TimerCallback callback) {
		this(delay,delay,callback);
	}

	/**
	 * Creates a new repeating timer with an initial and continual delay. 
	 * @param initialDelay the delay to use for the first timer callbacks.
	 * @param delay the delay to use for subsequent timer callbacks.
	 * @param callback the callback the be called with the timer fires.
	 */
	public GhidraSwinglessTimer(int initialDelay, int delay, TimerCallback callback) {
		this.callback = callback;
		this.delay = delay;
		this.initialDelay = initialDelay;
		this.repeats = true;
	}

	/**
	 * Returns the delay for all callbacks after the first callback.
	 * @return the delay for all callbacks after the first callback.
	 */
	public int getDelay() {
		return delay;
	}

	/**
	 * Returns the delay for the first callback.
	 * @return the delay for the first callback.
	 */
	public int getInitialDelay() {
		return initialDelay;
	}

	/**
	 * Returns true if this timer is set to repeating.
	 * @return true if this timer is set to repeating.
	 */
	public boolean isRepeats() {
		return repeats;
	}

	/**
	 * Sets the delay for all callbacks after the first callback
	 */
	public synchronized void setDelay(int delay) {
		this.delay = delay;
		if (isRunning()) {
			stop();
			start();
		}
	}

	/**
	 * Sets the delay for the first callbacks.
	 */
	public synchronized void setInitialDelay(int initialDelay) {
		this.initialDelay = initialDelay;
	}

	/**
	 * Sets whether this timer repeats.
	 * @param repeats if true, the timer will repeat, if false the timer will only fire once.
	 */
	public synchronized void setRepeats(boolean repeats) {
		this.repeats = repeats;
	}

	/**
	 * Sets the callback to be called when the timer fires.
	 */
	public synchronized void setTimerCallback(TimerCallback callback) {
		this.callback = callback;
	}

	/**
	 * Starts the timer.
	 */
	public synchronized void start() {
		if (timerTask != null) {
			return;
		}
		timerTask = new MyTimerTask();
		incrementCount();
		getTimer().schedule(timerTask, initialDelay, delay);	
	}

	/**
	 * Stops the timer.
	 */
	public synchronized void stop() {
		if (timerTask != null) {
			timerTask.cancel();
			timerTask = null;
			decrementCount();
		}
	}

	/**
	 * Returns true if the timer is running.
	 */
	public synchronized boolean isRunning() {
		return timerTask != null;
	}


	class MyTimerTask extends TimerTask {
		@Override
		public void run() {
			TimerCallback c;
			synchronized (GhidraSwinglessTimer.this) {
				c = callback;
				if (!repeats) {
					timerTask.cancel();
					timerTask = null;
					decrementCount();
				}
			}
			if (c != null) {
				c.timerFired();
			}
		}
	}
	static class CleanupTimerTask extends TimerTask {

		@Override
		public void run() {
			cleanupTimer();
		}
		
	}
	public static void main(String[] args) throws InterruptedException {
		final GhidraTimer t = new GhidraSwinglessTimer(500, null);
		
		TimerCallback callback1 = new TimerCallback() {
			int i = 0;
			public void timerFired() {
				System.out.println("A: "+i);
				if (++i == 20) {
					t.stop();
				}
			}
		};
		t.setTimerCallback(callback1);
		t.start();

		final GhidraTimer t2 = new GhidraSwinglessTimer(50, null);
		
		TimerCallback callback2 = new TimerCallback() {
			int i = 0;
			public void timerFired() {
				System.out.println("B: "+i);
				if (++i == 100) {
					t2.stop();
				}
			}
		};
		t2.setInitialDelay(250);
		t2.setTimerCallback(callback2);
		t2.start();

		
		System.err.println("waiting");
		Thread.sleep(20000);
		synchronized(GhidraSwinglessTimer.class) {
			if (cleanupTask == null) {
				throw new AssertException("cleanup timer is null");
			}
		}
		
		final GhidraTimer t3 = new GhidraSwinglessTimer(50, null);
		
		TimerCallback callback3 = new TimerCallback() {
			int i = 0;
			public void timerFired() {
				System.out.println("C: "+i);
				if (++i == 100) {
					t3.stop();
				}
			}
		};
		t3.setInitialDelay(250);
		t3.setTimerCallback(callback3);
		t3.start();

		
		System.err.println("waiting");
		Thread.sleep(20000);
		synchronized(GhidraSwinglessTimer.class) {
			if (cleanupTask == null) {
				throw new AssertException("cleanup timer is null");
			}
		}

		System.err.println("wait for cleanup;");
		Thread.sleep(CLEANUP_TIMER_THREAD_DELAY);
		synchronized(GhidraSwinglessTimer.class) {
			if (cleanupTask != null) {
				throw new AssertException("cleanup timer did not go away");
			}
		}
		System.err.println("done");
	}

}
