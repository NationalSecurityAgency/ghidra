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

import java.nio.file.Path;
import java.util.concurrent.*;

import ghidra.app.plugin.core.go.exception.StopWaitingException;
import ghidra.util.Msg;
import ghidra.util.Swing;

public class CheckForFileProcessedRunnable extends CheckPeriodicallyRunnable {

	/**
	 * How long to wait before asking to continue waiting after the url has been sent to a listening
	 * Ghidra
	 */
	public static int WAIT_FOR_PROCESSING_DELAY_MS = 500;

	/**
	 * How frequently to ask to continue waiting after Wait is selected
	 */
	public static int WAIT_FOR_PROCESSING_PERIOD_MS = 60_000;

	/**
	 * Maximum amount of time to wait for the file to be processed
	 */
	public static int MAX_WAIT_FOR_PROCESSING_MIN = 1;

	private Path filePath;
	private StopWaitingException stopWaitingException;

	public CheckForFileProcessedRunnable(Path filePath, int period, TimeUnit timeUnit) {
		super(false, period, timeUnit, () -> filePath.toFile().exists());
		this.filePath = filePath;
	}

	/**
	 * This constructor is used to create the thread that will show the wait dialog
	 * @param executor the internal executor that should have 2 threads
	 * @param filePath the path to the file to check
	 * @param period the interval to show the dialog
	 * @param timeUnit the units for the period
	 */
	private CheckForFileProcessedRunnable(ScheduledExecutorService executor, Path filePath,
			int period, TimeUnit timeUnit) {
		super(executor, true, period, timeUnit, () -> filePath.toFile().exists());
		this.filePath = filePath;
	}

	public void run() {
		try {
			if (checkCondition.call()) {
				try {
					if (showDialog) {
						// show the dialog in a blocking action. This will throw a StopWaitingException
						// if they answer No. Otherwise, they want to keep waiting.
						dialog.showDialog();
					}

					// if their response was WAIT, reset the timer
					executor.schedule(this, period, timeUnit);
				}
				catch (StopWaitingException e) {
					this.stopWaitingException = e;
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
			Swing.runNow(() -> Msg.showError(this, null, "GhidraGo Unable to Check File",
				"GhidraGo could not check existence of file at " + filePath, e));
			dispose();
		}
	}

	@Override
	public void startChecking(int delay, TimeUnit delayTimeUnit) throws StopWaitingException {
		dialog.reset();
		try {
			// start thread to check frequently
			super.startChecking(delay, delayTimeUnit);

			// start thread for showing dialog
			executor.schedule(new CheckForFileProcessedRunnable(executor, filePath,
				WAIT_FOR_PROCESSING_PERIOD_MS, TimeUnit.MILLISECONDS), WAIT_FOR_PROCESSING_DELAY_MS,
				TimeUnit.MILLISECONDS);
		}
		catch (RejectedExecutionException e) {
			if (dialog.isAnsweredNo()) {
				throw new StopWaitingException();
			}
		}
	}

	public void awaitTermination() throws StopWaitingException {
		try {
			executor.awaitTermination(MAX_WAIT_FOR_PROCESSING_MIN, TimeUnit.MINUTES);
			if (dialog.isAnsweredNo()) {
				throw new StopWaitingException();
			}

			if (this.stopWaitingException != null) {
				throw this.stopWaitingException;
			}
		}
		catch (InterruptedException e) {
			// this is okay
		}
	}
}
