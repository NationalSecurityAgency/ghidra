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

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ExtensionPoint;
import ghidra.util.task.TaskMonitor;

/**
 * NOTE:  ALL BinaryAnalysisCommand CLASSES MUST END IN "BinaryAnalysisCommand".  If not,
 * the ClassSearcher will not find them.
 *
 */
public interface BinaryAnalysisCommand extends ExtensionPoint {
	/**
	 * Returns TRUE if this command can be applied
	 * to the given domain object.
	 * @param program the domain object to inspect.
	 * @return TRUE if this command can be applied
	 */
	public boolean canApply(Program program);
	/**
	 * Applies the command to the given domain object.
	 * @param program domain object that this command is to be applied.
	 * @param monitor the task monitor
	 * @return true if the command applied successfully
	 */
	public boolean applyTo(Program program, TaskMonitor monitor) throws Exception;
	/**
	 * Returns the status message indicating the status of the command.
	 * @return reason for failure, or null if the status of the command 
	 *         was successful
	 */
	public MessageLog getMessages();
	/**
	 * Returns the name of this command. 
	 * @return the name of this command
	 */
	public String getName();
}
