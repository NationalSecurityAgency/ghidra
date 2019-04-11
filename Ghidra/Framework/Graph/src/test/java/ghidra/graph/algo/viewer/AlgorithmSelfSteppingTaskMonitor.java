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

import ghidra.util.Msg;

/**
 * Stepping task monitor that will proceed to the next step after the specified delay
 */
public class AlgorithmSelfSteppingTaskMonitor extends AlgorithmSteppingTaskMonitor {

	private int stepTime;

	public AlgorithmSelfSteppingTaskMonitor(int stepTime) {
		this.stepTime = stepTime;
	}

	@Override
	public void pause() {

		if (isCancelled()) {
			return; // no pausing after cancelled
		}

		notifyStepReady();

		synchronized (this) {

			try {
				wait(stepTime);
			}
			catch (InterruptedException e) {
				Msg.debug(this, "Interrupted waiting for next step", e);
			}

		}
	}
}
