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
// Shows how to report progress to the GUI. 
//@author ghidra
//@category Examples

import ghidra.app.script.GhidraScript;

public class ProgressExampleScript extends GhidraScript {

	@Override
	public void run() throws Exception {

		// You have to call initialize() in order for Ghidra to know to show the progress bar.
		monitor.initialize(10);

		for (int i = 0; i < 10; i++) {
			// Note: any script wishing to be responsive to a cancellation from the GUI needs to 
			// call checkCancelled()
			monitor.checkCanceled();

			Thread.sleep(1000); // pause a bit so we can see progress

			monitor.incrementProgress(1); // update the progress
			monitor.setMessage("Working on " + i); // update the status message			
		}
	}

}
