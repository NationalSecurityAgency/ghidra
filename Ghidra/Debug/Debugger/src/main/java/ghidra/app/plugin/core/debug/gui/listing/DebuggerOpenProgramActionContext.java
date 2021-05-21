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
package ghidra.app.plugin.core.debug.gui.listing;

import java.util.Objects;

import docking.ActionContext;
import ghidra.framework.model.DomainFile;

public class DebuggerOpenProgramActionContext extends ActionContext {
	private final DomainFile df;
	private final int hashCode;

	public DebuggerOpenProgramActionContext(DomainFile df) {
		this.df = df;
		this.hashCode = Objects.hash(getClass(), df);
	}

	public DomainFile getDomainFile() {
		return df;
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
		if (!(obj instanceof DebuggerOpenProgramActionContext)) {
			return false;
		}
		DebuggerOpenProgramActionContext that = (DebuggerOpenProgramActionContext) obj;
		if (!this.df.equals(that.df)) {
			return false;
		}
		return true;
	}
}
