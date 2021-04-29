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
package agent.gdb.manager;

import ghidra.util.TriConsumer;

/**
 * A listener for changes in GDB's state
 */
public interface GdbStateListener extends TriConsumer<GdbState, GdbState, GdbCause> {
	/**
	 * The state has changed because of the given cause
	 * 
	 * @param state the new state
	 * @param cause the reason for the change
	 */
	void stateChanged(GdbState state, GdbCause cause);

	@Override
	default void accept(GdbState oldSt, GdbState newSt, GdbCause u) {
		stateChanged(newSt, u);
	}
}
