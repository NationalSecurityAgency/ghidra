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
package ghidra.util.classfinder;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Task for searching for classes.  This allows for a runtime refresh of scanned classes.
 */
public class ClassSearchTask extends Task {

	public ClassSearchTask() {
		super("Refreshing List of Ghidra Class Files", true, false, true);
	}

	@Override
	public void run(final TaskMonitor taskMonitor) {

		try {
			ClassSearcher.search(true, taskMonitor);
		}
		catch (CancelledException e) {
			// user cancelled
		}
	}
}
