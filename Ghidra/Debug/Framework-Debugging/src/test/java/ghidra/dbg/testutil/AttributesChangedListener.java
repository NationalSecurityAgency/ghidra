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
package ghidra.dbg.testutil;

import java.util.Collection;
import java.util.Map;

import ghidra.dbg.DebuggerModelListener;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.testutil.AttributesChangedListener.AttributesChangedInvocation;

public class AttributesChangedListener extends
		AbstractInvocationListener<AttributesChangedInvocation> implements DebuggerModelListener {
	public static class AttributesChangedInvocation {
		public final TargetObject parent;
		public final Collection<String> removed;
		public final Map<String, ?> added;

		public AttributesChangedInvocation(TargetObject parent, Collection<String> removed,
				Map<String, ?> added) {
			this.parent = parent;
			this.removed = removed;
			this.added = added;
		}
	}

	@Override
	public void attributesChanged(TargetObject parent, Collection<String> removed,
			Map<String, ?> added) {
		record(new AttributesChangedInvocation(parent, removed, added));
	}
}
