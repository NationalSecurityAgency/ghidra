/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.framework.cmd;

import ghidra.framework.model.DomainObject;

/**
 * Interface to define a change made to a domain object.
 *
 */
public interface Command {

	/**
	 * Applies the command to the given domain object.
	 * 
	 * @param obj domain object that this command is to be applied.
	 * 
	 * @return true if the command applied successfully
	 */
	public boolean applyTo(DomainObject obj);
	
	/**
	 * Returns the status message indicating the status of the command.
	 * 
	 * @return reason for failure, or null if the status of the command 
	 *         was successful
	 */
	public String getStatusMsg();
	
	/**
	 * Returns the name of this command.
	 * 
	 * @return the name of this command
	 */
	public String getName();
}
