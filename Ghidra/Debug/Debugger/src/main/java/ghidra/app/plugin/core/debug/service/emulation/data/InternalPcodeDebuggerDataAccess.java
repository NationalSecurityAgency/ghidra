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
package ghidra.app.plugin.core.debug.service.emulation.data;

import ghidra.debug.api.modules.DebuggerAddressTranslator;
import ghidra.debug.api.target.Target;
import ghidra.lifecycle.Internal;
import ghidra.pcode.exec.trace.data.InternalPcodeTraceDataAccess;
import ghidra.trace.model.TraceTimeViewport;

@Internal
public interface InternalPcodeDebuggerDataAccess extends InternalPcodeTraceDataAccess {
	/**
	 * {@return the address translator or null. If null is returned, then bytes cannot be loaded
	 * from mapped images.}
	 */
	DebuggerAddressTranslator getAddressTranslator();

	/**
	 * {@return the target or null}
	 */
	Target getTarget();

	/**
	 * Check if the associated trace represents a live target
	 * <p>
	 * To be live, there must be a non-null target, that target must still be valid, i.e., connected
	 * to a live debugger, and the current snapshot must have a viewport incorporating the target's
	 * current snapshot.
	 * 
	 * @return true if alive or false if dead/offline
	 */
	default boolean isLive() {
		Target target = getTarget();
		if (target == null || !target.isValid()) {
			return false;
		}
		TraceTimeViewport viewport = getViewport();
		for (long s : viewport.getReversedSnaps()) {
			if (target.getSnap() == s) {
				return true;
			}
		}
		return false;
	}
}
