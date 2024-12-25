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
package ghidra.debug.api.model;

import docking.DefaultActionContext;
import ghidra.trace.model.target.path.KeyPath;

/**
 * Really just used by scripts to get a path into an action context
 */
public class DebuggerSingleObjectPathActionContext extends DefaultActionContext {
	private final KeyPath path;

	public DebuggerSingleObjectPathActionContext(KeyPath path) {
		this.path = path;
	}

	public KeyPath getPath() {
		return path;
	}
}
