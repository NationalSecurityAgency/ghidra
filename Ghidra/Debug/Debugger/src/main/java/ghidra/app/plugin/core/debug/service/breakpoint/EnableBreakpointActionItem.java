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
package ghidra.app.plugin.core.debug.service.breakpoint;

import java.util.Objects;
import java.util.concurrent.CompletableFuture;

import ghidra.dbg.target.TargetTogglable;

public class EnableBreakpointActionItem implements BreakpointActionItem {
	private final TargetTogglable togglable;

	public EnableBreakpointActionItem(TargetTogglable togglable) {
		this.togglable = togglable;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof EnableBreakpointActionItem)) {
			return false;
		}
		EnableBreakpointActionItem that = (EnableBreakpointActionItem) obj;
		if (this.togglable != that.togglable) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		return Objects.hash(getClass(), togglable);
	}

	@Override
	public CompletableFuture<Void> execute() {
		return togglable.enable();
	}
}
