/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.framework.task;

/**
 * A Dummy implementation to that listeners can subclass this and not have to fill in methods they
 * don't need.
 */
public class GTaskListenerAdapter implements GTaskListener {

	@Override
	public void taskCompleted(GScheduledTask task, GTaskResult result) {
		// stub
	}

	@Override
	public void taskGroupScheduled(GTaskGroup group) {
		// stub
	}

	@Override
	public void taskScheduled(GScheduledTask scheduledTask) {
		// stub
	}

	@Override
	public void taskGroupStarted(GTaskGroup taskGroup) {
		// stub
	}

	@Override
	public void taskStarted(GScheduledTask task) {
		// stub
	}

	@Override
	public void initialize() {
		// stub
	}

	@Override
	public void taskGroupCompleted(GTaskGroup taskGroup) {
		// stub
	}

	@Override
	public void suspendedStateChanged(boolean suspended) {
		// stub
	}

}
