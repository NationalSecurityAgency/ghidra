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

import utility.function.Dummy;

/**
 * A class that run the client's runnable on the Swing thread.  Repeated requests will get buffered
 * until the max delay is reached.   
 */
public class BufferedSwingRunner extends AbstractSwingUpdateManager {

	private Runnable nextRunnable;

	/**
	 * Constructs a new SwingUpdateManager
	 * <p>
	 * <b>Note: </b>The <code>minDelay</code> will always be at least {@link #MIN_DELAY_FLOOR}, 
	 * regardless of the given value.
	 *
	 * @param minDelay the minimum number of milliseconds to wait once the event stream stops
	 *                 coming in before actually updating the screen.
	 * @param maxDelay the maximum amount of time to wait between gui updates.
	 */
	public BufferedSwingRunner(int minDelay, int maxDelay) {
		super(minDelay, maxDelay, DEFAULT_NAME);
	}

	public BufferedSwingRunner() {
		super(DEFAULT_MIN_DELAY, DEFAULT_MAX_DELAY, DEFAULT_NAME);
	}

	@Override
	protected void swingDoWork() {
		Runnable currentRunnable = prepareCurrentRunnable();
		currentRunnable.run();
	}

	/**
	 * Runs the given runnable.  If this is the first call to <code>run</code>, then do the work
	 * immediately; otherwise, buffer the request until the timeout has expired.
	 * 
	 * <p>See the header of {@link AbstractSwingUpdateManager} for details on the update process.
	 * 
	 * @param r the task to run on the Swing thread
	 */
	public synchronized void run(Runnable r) {
		this.nextRunnable = r;
		update();
	}

	/**
	 * Runs the given runnable later, buffering the request until the timeout has expired.
	 * 
	 * <p>See the header of {@link AbstractSwingUpdateManager} for details on the update process.
	 * 
	 * @param r the task to run on the Swing thread
	 */
	public synchronized void runLater(Runnable r) {
		this.nextRunnable = r;
		updateLater();
	}

	private synchronized Runnable prepareCurrentRunnable() {
		Runnable currentRunnable = nextRunnable;
		nextRunnable = null;
		return Dummy.ifNull(currentRunnable);
	}
}
