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
package ghidra.app.plugin.core.debug.gui.tracecalltree;

import java.util.Objects;

import docking.DefaultActionContext;
import ghidra.program.model.address.Address;
import ghidra.trace.model.Trace;

public class TraceCallTreeLogContext extends DefaultActionContext {
	private final Trace trace;
	private final Address dynamicPC;
	private final int hashCode;

	public TraceCallTreeLogContext(TraceCallTreeProvider provider, Trace trace, Address dynamicPC) {
		super(provider);
		this.trace = trace;
		this.dynamicPC = dynamicPC;
		hashCode = Objects.hash(getClass(), trace, dynamicPC);
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof TraceCallTreeLogContext that)) {
			return false;
		}

		if (!Objects.equals(this.trace, that.trace)) {
			return false;
		}

		if (!Objects.equals(this.dynamicPC, that.dynamicPC)) {
			return false;
		}

		return true;
	}

	@Override
	public int hashCode() {
		return hashCode;
	}
}
