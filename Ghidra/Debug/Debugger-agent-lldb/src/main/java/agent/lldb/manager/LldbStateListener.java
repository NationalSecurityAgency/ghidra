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
package agent.lldb.manager;

import SWIG.StateType;
import ghidra.util.TriConsumer;

/**
 * A listener for changes in LLDB's state
 */
public interface LldbStateListener extends TriConsumer<StateType, StateType, LldbCause> {
	/**
	 * The state has changed because of the given cause
	 * 
	 * @param state the new state
	 * @param cause the reason for the change
	 */
	void stateChanged(StateType state, LldbCause cause);

	@Override
	default void accept(StateType oldVal, StateType newVal, LldbCause u) {
		stateChanged(newVal, u);
	}
}
