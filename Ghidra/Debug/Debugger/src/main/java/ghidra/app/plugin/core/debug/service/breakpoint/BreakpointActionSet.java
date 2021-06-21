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

import java.util.LinkedHashSet;
import java.util.concurrent.CompletableFuture;

import ghidra.async.AsyncFence;
import ghidra.dbg.target.*;

/**
 * A de-duplicated collection of target breakpoint actions necessary to implement a logical
 * breakpoint action.
 */
public class BreakpointActionSet extends LinkedHashSet<BreakpointActionItem> {

	public EnableBreakpointActionItem planEnable(TargetBreakpointLocation loc) {
		if (loc instanceof TargetTogglable) {
			EnableBreakpointActionItem action =
				new EnableBreakpointActionItem((TargetTogglable) loc);
			add(action);
			return action;
		}
		TargetBreakpointSpec spec = loc.getSpecification();
		if (spec instanceof TargetTogglable) {
			EnableBreakpointActionItem action = new EnableBreakpointActionItem(spec);
			add(action);
			return action;
		}
		return null;
	}

	public DisableBreakpointActionItem planDisable(TargetBreakpointLocation loc) {
		if (loc instanceof TargetTogglable) {
			DisableBreakpointActionItem action =
				new DisableBreakpointActionItem((TargetTogglable) loc);
			add(action);
			return action;
		}
		TargetBreakpointSpec spec = loc.getSpecification();
		if (spec instanceof TargetTogglable) {
			DisableBreakpointActionItem action = new DisableBreakpointActionItem(spec);
			add(action);
			return action;
		}
		return null;
	}

	public DeleteBreakpointActionItem planDelete(TargetBreakpointLocation loc) {
		if (loc instanceof TargetDeletable) {
			DeleteBreakpointActionItem action =
				new DeleteBreakpointActionItem((TargetDeletable) loc);
			add(action);
			return action;
		}
		TargetBreakpointSpec spec = loc.getSpecification();
		if (spec instanceof TargetTogglable) {
			DeleteBreakpointActionItem action =
				new DeleteBreakpointActionItem((TargetDeletable) spec);
			add(action);
			return action;
		}
		return null;
	}

	/**
	 * Carry out the actions in the order they were added
	 * 
	 * @return a future which completes when the actions have all completed
	 */
	public CompletableFuture<Void> execute() {
		AsyncFence fence = new AsyncFence();
		for (BreakpointActionItem item : this) {
			fence.include(item.execute());
		}
		return fence.ready();
	}
}
