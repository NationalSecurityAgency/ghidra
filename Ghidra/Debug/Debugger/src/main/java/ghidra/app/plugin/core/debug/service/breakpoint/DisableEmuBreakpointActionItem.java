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

import java.util.concurrent.CompletableFuture;

import db.Transaction;
import ghidra.async.AsyncUtils;
import ghidra.trace.model.breakpoint.TraceBreakpoint;

public record DisableEmuBreakpointActionItem(TraceBreakpoint bpt, long snap)
		implements BreakpointActionItem {
	@Override
	public CompletableFuture<Void> execute() {
		try (Transaction tx =
			bpt.getTrace().openTransaction("Disable Emulated Breakpoint")) {
			bpt.setEmuEnabled(snap, false);
		}
		return AsyncUtils.nil();
	}
}
