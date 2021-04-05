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
package agent.gdb.manager.impl;

import agent.gdb.manager.GdbCause;
import agent.gdb.manager.GdbState;

/**
 * The interface for GDB events
 *
 * @param <T> the type of parsed information detailing the event
 */
public interface GdbEvent<T> extends GdbCause {

	/**
	 * Get the information detailing the event
	 * 
	 * @return the information
	 */
	public T getInfo();

	/**
	 * Use {@link GdbPendingCommand#claim(GdbEvent)} instead
	 * 
	 * @param cause the cause
	 */
	public void claim(GdbPendingCommand<?> cause);

	/**
	 * If claimed, get the cause of this event
	 * 
	 * @return the cause
	 */
	public GdbCause getCause();

	/**
	 * Use {@link GdbPendingCommand#steal(GdbEvent)} instead
	 */
	public void steal();

	/**
	 * Check if this event is stolen
	 * 
	 * A stolen event should not be processed further, except by the thief
	 * 
	 * @return true if stolen, false otherwise
	 */
	public boolean isStolen();

	/**
	 * If this event implies a new GDB state, get that state
	 * 
	 * @return the new state, or null for no change
	 */
	public GdbState newState();
}
