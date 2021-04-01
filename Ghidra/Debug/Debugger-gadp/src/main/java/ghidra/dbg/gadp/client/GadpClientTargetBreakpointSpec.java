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
package ghidra.dbg.gadp.client;

import java.util.concurrent.CompletableFuture;

import ghidra.dbg.gadp.protocol.Gadp;
import ghidra.dbg.target.TargetBreakpointSpec;
import ghidra.util.datastruct.ListenerSet;

public interface GadpClientTargetBreakpointSpec
		extends GadpClientTargetObject, TargetBreakpointSpec {

	@Override
	default CompletableFuture<Void> toggle(boolean enabled) {
		getDelegate().assertValid();
		return getModel().sendChecked(Gadp.BreakToggleRequest.newBuilder()
				.setPath(GadpValueUtils.makePath(getPath()))
				.setEnabled(enabled),
			Gadp.BreakToggleReply.getDefaultInstance()).thenApply(rep -> null);
	}

	@Override
	default CompletableFuture<Void> disable() {
		return toggle(false);
	}

	@Override
	default CompletableFuture<Void> enable() {
		return toggle(true);
	}

	@Override
	default void addAction(TargetBreakpointAction action) {
		getDelegate().getActions(true).add(action);
	}

	@Override
	default void removeAction(TargetBreakpointAction action) {
		ListenerSet<TargetBreakpointAction> actions = getDelegate().getActions(false);
		if (actions != null) {
			actions.remove(action);
		}
	}
}
