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

import java.util.concurrent.atomic.AtomicBoolean;

public class TaskDialogSpy extends TaskDialog {
	private AtomicBoolean shown = new AtomicBoolean();

	public TaskDialogSpy(Task task) {
		super(task);
	}

	@Override
	protected void doShow() {
		shown.set(true);
		super.doShow();
	}

	boolean wasShown() {
		return shown.get();
	}
}
