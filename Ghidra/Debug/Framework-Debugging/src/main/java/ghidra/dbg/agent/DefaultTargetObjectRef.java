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
package ghidra.dbg.agent;

import java.util.List;

import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.attributes.TargetObjectRef;

public class DefaultTargetObjectRef implements TargetObjectRef {
	private final DebuggerObjectModel model;
	private final List<String> path;
	private final int hash;

	public DefaultTargetObjectRef(DebuggerObjectModel model, List<String> path) {
		this.model = model;
		this.path = path;
		this.hash = computeHashCode();
	}

	@Override
	public boolean equals(Object obj) {
		return doEquals(obj);
	}

	@Override
	public int hashCode() {
		return hash;
	}

	@Override
	public DebuggerObjectModel getModel() {
		return model;
	}

	@Override
	public List<String> getPath() {
		return path;
	}

	@Override
	public String toString() {
		return "<Ref to " + path + " in " + model + ">";
	}
}
