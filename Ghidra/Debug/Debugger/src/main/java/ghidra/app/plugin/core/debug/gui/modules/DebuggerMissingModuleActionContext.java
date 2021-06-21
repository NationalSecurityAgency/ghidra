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
package ghidra.app.plugin.core.debug.gui.modules;

import java.util.Objects;

import docking.ActionContext;
import ghidra.trace.model.modules.TraceModule;

public class DebuggerMissingModuleActionContext extends ActionContext {
	private final TraceModule module;
	private final int hashCode;

	public DebuggerMissingModuleActionContext(TraceModule module) {
		this.module = Objects.requireNonNull(module);
		this.hashCode = Objects.hash(getClass(), module);
	}

	public TraceModule getModule() {
		return module;
	}

	@Override
	public int hashCode() {
		return hashCode;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof DebuggerMissingModuleActionContext)) {
			return false;
		}
		DebuggerMissingModuleActionContext that = (DebuggerMissingModuleActionContext) obj;
		if (!this.module.equals(that.module)) {
			return false;
		}
		return true;
	}
}
