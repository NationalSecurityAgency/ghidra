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
package ghidra.app.plugin.core.go.ipc;

import java.util.concurrent.*;

import ghidra.app.plugin.core.go.dialog.GhidraGoWaitForListenerDialog;
import ghidra.app.plugin.core.go.exception.StartedGhidraProcessExitedException;
import ghidra.app.plugin.core.go.exception.StopWaitingException;
import ghidra.util.Swing;

public abstract class CheckPeriodicallyRunnable implements Runnable {

	protected static GhidraGoWaitForListenerDialog dialog = new GhidraGoWaitForListenerDialog();

	protected boolean showDialog;
	protected int period;
	protected TimeUnit timeUnit;
	protected ScheduledExecutorService executor;
	protected Callable<Boolean> checkCondition;

	public CheckPeriodicallyRunnable(boolean showDialog,
			int period, TimeUnit timeUnit, Callable<Boolean> checkCondition) {
		this.showDialog = showDialog;
		this.period = period;
		this.timeUnit = timeUnit;
		this.checkCondition = checkCondition;

		// two threads; one for checking quickly without showing dialog, another for showing dialog
		this.executor = Executors.newScheduledThreadPool(2);
	}

	protected CheckPeriodicallyRunnable(ScheduledExecutorService executor, boolean showDialog,
			int period,
			TimeUnit timeUnit, Callable<Boolean> checkCondition) {
		this(showDialog, period, timeUnit, checkCondition);
		this.executor = executor;
	}

	/**
	 * Begins checking the check condition in a thread
	 * @param delay the amount of time to wait to being checking
	 * @param delayTimeUnit the units for the amount of time
	 * @throws StopWaitingException in the event a dialog is answered to stop waiting
	 */
	public void startChecking(int delay,
			TimeUnit delayTimeUnit) throws StopWaitingException {
		executor.schedule(this, delay, delayTimeUnit);
	}

	public abstract void awaitTermination()
			throws StopWaitingException, StartedGhidraProcessExitedException;

	public void dispose() {
		executor.shutdownNow();
		Swing.runNow(dialog::close);
	}
}
