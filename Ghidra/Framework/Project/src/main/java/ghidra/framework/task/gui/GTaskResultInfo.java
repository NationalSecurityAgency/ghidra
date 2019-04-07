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
package ghidra.framework.task.gui;

import ghidra.framework.task.GTaskResult;

/**
 * An item that wraps {@link GTaskResult}s that are to be put into JLists in order to add more
 * information.
 */
class GTaskResultInfo {
	private GTaskResult result;

	GTaskResultInfo(GTaskResult result) {
		this.result = result;
	}

	GTaskResult getResult() {
		return result;
	}

	@Override
	public String toString() {
		if (result == null) {
			return "---- New Transaction ------";
		}
		return result.toString();
	}
}
