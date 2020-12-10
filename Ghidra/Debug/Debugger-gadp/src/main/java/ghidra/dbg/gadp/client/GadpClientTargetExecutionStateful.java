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

import ghidra.dbg.gadp.client.annot.GadpAttributeChangeCallback;
import ghidra.dbg.target.TargetExecutionStateful;
import ghidra.dbg.util.ValueUtils;

public interface GadpClientTargetExecutionStateful
		extends GadpClientTargetObject, TargetExecutionStateful<GadpClientTargetExecutionStateful> {

	default TargetExecutionState stateFromObj(Object obj) {
		return ValueUtils.expectType(obj, TargetExecutionState.class, this,
			STATE_ATTRIBUTE_NAME, TargetExecutionState.INACTIVE);
	}

	@GadpAttributeChangeCallback(STATE_ATTRIBUTE_NAME)
	default void handleStateChanged(Object state) {
		getDelegate().listeners.fire(TargetExecutionStateListener.class)
				.executionStateChanged(this, stateFromObj(state));
	}
}
