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

import java.util.LinkedList;

import ghidra.async.AsyncReference;

public abstract class AbstractInvocationListener<T> {
	public final LinkedList<T> invocations = new LinkedList<>();
	public final AsyncReference<Integer, Void> count = new AsyncReference<>(0);

	protected void record(T rec) {
		invocations.add(rec);
		count.set(invocations.size(), null);
	}

	public void clear() {
		invocations.clear();
		count.set(0, null);
	}
}
