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

import java.awt.Component;
import java.util.Collection;
import java.util.List;

import docking.ComponentProvider;
import docking.DefaultActionContext;
import ghidra.trace.model.target.TraceObjectValue;

public class DebuggerObjectActionContext extends DefaultActionContext {
	private final List<TraceObjectValue> objectValues;
	private final long snap;

	public DebuggerObjectActionContext(Collection<TraceObjectValue> objectValues,
			ComponentProvider provider, Component sourceComponent, long snap) {
		super(provider, sourceComponent);
		this.objectValues = List.copyOf(objectValues);
		this.snap = snap;
	}

	public List<TraceObjectValue> getObjectValues() {
		return objectValues;
	}

	public long getSnap() {
		return snap;
	}
}
