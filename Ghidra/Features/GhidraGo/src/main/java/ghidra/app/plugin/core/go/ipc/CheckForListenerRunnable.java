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

import ghidra.app.plugin.core.go.exception.StartedGhidraProcessExitedException;
import ghidra.app.plugin.core.go.exception.StopWaitingException;
import ghidra.util.Msg;
import ghidra.util.Swing;

public class CheckForListenerRunnable extends CheckPeriodicallyRunnable {
	/**
	 * If a listening Ghidra needs to be started, how long to wait before asking to continue 
	 * waiting 
	 */
	public static int WAIT_FOR_LISTENER_DELAY_MS = 30_000;

	/**
	 * How frequently to ask to continue waiting after Wait is selected
	 */
	public static int WAIT_FOR_LISTENER_PERIOD_MS = 60_000;

	/**
	 * Maximum amount of time to wait for a listening Ghidra
	 */
	public static int MAX_WAIT_FOR_LISTENER_MIN = 5;

	private Process process;
	private StopWaitingException stopWaitingException;
	private StartedGhidraProcessExitedException startedGhidraProcessExitedException;

	public CheckForListenerRunnable(Process p, int period, TimeUnit timeUnit,
			Callable<Boolean> checkCondition) {
		super(false, period, timeUnit, checkCondition);
		this.process = p;
	}

	private CheckForListenerRunnable(ScheduledExecutorService executor, Process p, int period,
			TimeUnit timeUnit, Callable<Boolean> checkCondition) {
		super(executor, true, period, timeUnit, checkCondition);
		this.process = p;
	}

	public void run() {
		try {
			if (checkCondition.call()) {
				try {
					checkProcessDidNotExit(process);
					if (showDialog) {
						Msg.info(this, "Waiting for GhidraGo to listen for new files...");
						// show the dialog in a blocking action. This will throw a StopWaitingException
						// if they answer No. Otherwise, they want to keep waiting.
						dialog.showDialog();
					}
					executor.schedule(this, period, timeUnit);
				}
				catch (StopWaitingException e) {
					this.stopWaitingException = e;
					dispose();
				}
				catch (StartedGhidraProcessExitedException e) {
					this.startedGhidraProcessExitedException = e;
					dispose();
				}
				catch (RejectedExecutionException e) {
					// this is okay, executor has been shutdown
					dispose();
				}
			}
			else {
				dispose();
			}
		}
		catch (Exception e) {
			Swing.runNow(() -> Msg.showError(this, null, "GhidraGo Unable to Check For Listener",
				"GhidraGo could not check for a listener.", e));
			dispose();
		}
	}

	/**
	 * checks to see if Ghidra process exited early, In the event Ghidra exits early, 
	 * a runtime exception is thrown
	 * @param p Ghidra process
	 * @throws StartedGhidraProcessExitedException if the Ghidra process has an exit value
	 */
	private void checkProcessDidNotExit(Process p) throws StartedGhidraProcessExitedException {
		if (p != null) {
			try {
				int exitValue = p.exitValue();
				if (exitValue != 0)
					throw new StartedGhidraProcessExitedException(exitValue);
			}
			catch (IllegalThreadStateException e) {
				// this is okay, ghidraRun hasn't exited
			}
		}
	}

	@Override
	public void startChecking(int delay, TimeUnit delayTimeUnit) throws StopWaitingException {
		dialog.reset();
		try {
			// start thread to check frequently
			super.startChecking(delay, delayTimeUnit);

			// start thread for showing dialog
			executor.schedule(
				new CheckForListenerRunnable(executor, process, WAIT_FOR_LISTENER_PERIOD_MS,
					TimeUnit.MILLISECONDS, checkCondition),
				WAIT_FOR_LISTENER_DELAY_MS, TimeUnit.MILLISECONDS);
		}
		catch (RejectedExecutionException e) {
			if (dialog.isAnsweredNo()) {
				throw new StopWaitingException();
			}
		}
	}

	@Override
	public void awaitTermination()
			throws StopWaitingException, StartedGhidraProcessExitedException {
		try {
			executor.awaitTermination(MAX_WAIT_FOR_LISTENER_MIN, TimeUnit.MINUTES);

			if (dialog.isAnsweredNo()) {
				throw new StopWaitingException();
			}

			if (this.stopWaitingException != null) {
				throw this.stopWaitingException;
			}
			if (this.startedGhidraProcessExitedException != null) {
				throw this.startedGhidraProcessExitedException;
			}
		}
		catch (InterruptedException e) {
			// this is okay
		}
	}

}
