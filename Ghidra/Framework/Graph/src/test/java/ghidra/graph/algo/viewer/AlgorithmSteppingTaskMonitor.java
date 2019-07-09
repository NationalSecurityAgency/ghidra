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
package ghidra.graph.algo.viewer;

import java.util.HashSet;
import java.util.Set;

import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;
import utility.function.Callback;

/**
 * Task monitor that will trigger a {@link #wait()} when {@link #checkCanceled()} is called.  This
 * allows clients to watch algorithms as they proceed.
 */
public class AlgorithmSteppingTaskMonitor extends TaskMonitorAdapter {

	private Set<Callback> stepLisetners = new HashSet<>();

	public AlgorithmSteppingTaskMonitor() {
		setCancelEnabled(true);
	}

	public void addStepListener(Callback c) {
		stepLisetners.add(c);
	}

	@Override
	public void cancel() {
		super.cancel();
		step(); // wake-up any waiting threads
	}

	@Override
	public void checkCanceled() throws CancelledException {

		super.checkCanceled();

		pause();
	}

	/**
	 * Causes this monitor to perform at {@link #wait()}.  Call {@link #step()} to allow the
	 * client to continue.
	 */
	public void pause() {

		if (isCancelled()) {
			return; // no pausing after cancelled
		}

		notifyStepReady();

		synchronized (this) {

			try {
				wait();
			}
			catch (InterruptedException e) {
				Msg.debug(this, "Interrupted waiting for next step", e);
			}

		}
	}

	public void step() {
		synchronized (this) {
			notify();
		}
	}

	protected void notifyStepReady() {
		stepLisetners.forEach(l -> l.call());
	}
}
