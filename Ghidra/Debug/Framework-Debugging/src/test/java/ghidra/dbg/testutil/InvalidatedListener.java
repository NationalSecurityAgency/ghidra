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

import ghidra.dbg.DebuggerModelListener;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.testutil.InvalidatedListener.InvalidatedInvocation;

public class InvalidatedListener extends AbstractInvocationListener<InvalidatedInvocation>
		implements DebuggerModelListener {
	public static class InvalidatedInvocation {
		public final TargetObject object;
		public final TargetObject branch;
		public final String reason;

		public InvalidatedInvocation(TargetObject object, TargetObject branch, String reason) {
			this.object = object;
			this.branch = branch;
			this.reason = reason;
		}

		@Override
		public String toString() {
			return String.format("<InvalidatedInvocation '%s' because '%s'>", object, reason);
		}
	}

	@Override
	public void invalidated(TargetObject object, TargetObject branch, String reason) {
		record(new InvalidatedInvocation(object, branch, reason));
	}
}
