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
package agent.dbgeng.model.iface1;

import java.util.List;
import java.util.Map;

import agent.dbgeng.manager.DbgState;
import agent.dbgeng.model.iface2.DbgModelTargetObject;
import ghidra.dbg.target.TargetExecutionStateful;

/**
 * An interface which indicates this object is capable of launching targets.
 * 
 * The targets this launcher creates ought to appear in its successors.
 * 
 * @param <T> type for this
 */
public interface DbgModelTargetExecutionStateful
		extends DbgModelTargetObject, TargetExecutionStateful {

	public default TargetExecutionState convertState(DbgState state) {
		switch (state) {
			case RUNNING:
				return TargetExecutionState.RUNNING;
			case STOPPED:
			default:
				return TargetExecutionState.STOPPED;
		}
	}

	public default void setExecutionState(TargetExecutionState state, String reason) {
		if (isValid()) {
			changeAttributes(List.of(), Map.of( //
				STATE_ATTRIBUTE_NAME, state //
			), reason);
		}
	}

}
