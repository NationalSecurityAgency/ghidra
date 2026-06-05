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
import ghidra.debug.api.target.Target;
import ghidra.trace.model.breakpoint.TraceBreakpointLocation;

/**
 * A de-duplicated collection of breakpoint action items necessary to implement a logical breakpoint
 * action.
 * 
 * <p>
 * This will de-duplicate action items, but it does not check them for sanity. For example, deleting
 * a breakpoint then enabling it. Typically, all the items are the same type, so such sanity checks
 * are not necessary.
 */
public class BreakpointActionSet extends LinkedHashSet<BreakpointActionItem> {

	/**
	 * Add an item to enable a target breakpoint
	 * 
	 * @param target the target
	 * @param loc the target breakpoint
	 * @return the added item
	 */
	public EnableTargetBreakpointActionItem planEnableTarget(Target target,
			TraceBreakpointLocation loc) {
		EnableTargetBreakpointActionItem action = new EnableTargetBreakpointActionItem(target, loc);
		add(action);
		return action;
	}

	/**
	 * Add an item to enable an emulated breakpoint
	 * 
	 * @param loc the trace breakpoint
	 * @param snap the snap
	 * @return the added item
	 */
	public EnableEmuBreakpointActionItem planEnableEmu(TraceBreakpointLocation loc, long snap) {
		EnableEmuBreakpointActionItem action = new EnableEmuBreakpointActionItem(loc, snap);
		add(action);
		return action;
	}

	/**
	 * Add an item to disable a target breakpoint
	 * 
	 * @param target the target
	 * @param loc the target breakpoint
	 * @return the added item
	 */
	public DisableTargetBreakpointActionItem planDisableTarget(Target target,
			TraceBreakpointLocation loc) {
		DisableTargetBreakpointActionItem action =
			new DisableTargetBreakpointActionItem(target, loc);
		add(action);
		return action;
	}

	/**
	 * Add an item to disable an emulated breakpoint
	 * 
	 * @param loc the trace breakpoint
	 * @param snap the snap
	 * @return the added item
	 */
	public DisableEmuBreakpointActionItem planDisableEmu(TraceBreakpointLocation loc, long snap) {
		DisableEmuBreakpointActionItem action = new DisableEmuBreakpointActionItem(loc, snap);
		add(action);
		return action;
	}

	/**
	 * Add an item to delete a target breakpoint
	 * 
	 * @param target the target
	 * @param loc the target breakpoint
	 * @return the added item
	 */
	public DeleteTargetBreakpointActionItem planDeleteTarget(Target target,
			TraceBreakpointLocation loc) {
		DeleteTargetBreakpointActionItem action = new DeleteTargetBreakpointActionItem(target, loc);
		add(action);
		return action;
	}

	/**
	 * Add an item to delete an emulated breakpoint
	 * 
	 * @param loc the trace breakpoint
	 * @param snap the snap
	 * @return the added item
	 */
	public DeleteEmuBreakpointActionItem planDeleteEmu(TraceBreakpointLocation loc, long snap) {
		DeleteEmuBreakpointActionItem action = new DeleteEmuBreakpointActionItem(loc, snap);
		add(action);
		return action;
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
