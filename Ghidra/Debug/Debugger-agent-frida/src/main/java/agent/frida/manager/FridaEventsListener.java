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
package agent.frida.manager;

import agent.frida.frida.FridaRegionInfo;
import agent.frida.frida.FridaModuleInfo;

public interface FridaEventsListener {

	/**
	 * A session has been added
	 * 
	 * @param session a handle to the new session
	 * @param cause the cause of this event
	 */
	void sessionAdded(FridaSession session, FridaCause cause);

	/**
	 * A session has been replaced
	 * 
	 * @param session a handle to the new session
	 * @param cause the cause of this event
	 */
	void sessionReplaced(FridaSession session, FridaCause cause);

	/**
	 * A session has been removed
	 * 
	 * @param sessionId the ID of the now-defunct session
	 * @param cause the cause of this event
	 */
	void sessionRemoved(String sessionId, FridaCause cause);

	/**
	 * A different session has been selected (gained focus)
	 * 
	 * @param session a handle to the selected session
	 * @param cause the cause of this event
	 */
	void sessionSelected(FridaSession session, FridaCause cause);

	/**
	 * An Process has been added to the session
	 * 
	 * @param process a handle to the new process
	 * @param cause the cause of this event
	 */
	void processAdded(FridaProcess process, FridaCause cause);

	/**
	 * An Process has been replaced in the session
	 * 
	 * @param process a handle to the new process
	 * @param cause the cause of this event
	 */
	void processReplaced(FridaProcess process, FridaCause cause);

	/**
	 * An process has been removed from the session
	 * 
	 * @param processId the ID of the now-defunct process
	 * @param cause the cause of this event
	 */
	void processRemoved(String processId, FridaCause cause);

	/**
	 * A different process has been selected (gained focus)
	 * 
	 * @param process a handle to the selected process
	 * @param cause the cause of this event
	 */
	void processSelected(FridaProcess process, FridaCause cause);

	/**
	 * Execution has been started in an process
	 * 
	 * @param process a handle to the now-executing process
	 * @param cause the cause of this event
	 */
	void processStarted(FridaProcess process, FridaCause cause);

	/**
	 * Execution has terminated in an process
	 * 
	 * @param process a handle to the now-stopped process
	 * @param cause the cause of this event
	 */
	void processExited(FridaProcess process, FridaCause cause);

	/**
	 * A thread has been created
	 * 
	 * Use {@link FridaThread#getProcess()} to get a handle to the process in which the thread was
	 * created.
	 * 
	 * @param thread a handle to the new thread
	 * @param cause the cause of this event
	 */
	void threadCreated(FridaThread thread, FridaCause cause);

	/**
	 * A thread has been replaced
	 * 
	 * Use {@link FridaThread#getProcess()} to get a handle to the process in which the thread was
	 * created.
	 * 
	 * @param thread a handle to the new thread
	 * @param cause the cause of this event
	 */
	void threadReplaced(FridaThread thread, FridaCause cause);

	/**
	 * A thread's state has changed
	 * 
	 * @param thread a handle to the thread whose state has changed
	 * @param state the state to which the thread changed
	 * @param cause the cause of this event
	 * @param reason the reason for the state change
	 */
	void threadStateChanged(FridaThread thread, FridaState state, FridaCause cause, FridaReason reason);

	/**
	 * A thread has exited
	 * 
	 * @param thread the now-defunct thread
	 * @param process a handle to the process to which the thread belonged
	 * @param cause the cause of this event
	 */
	void threadExited(FridaThread thread, FridaProcess process, FridaCause cause);

	/**
	 * A different thread has been selected (gained focus)
	 * 
	 * @param thread a handle to the selected thread
	 * @param frame a handle to the current frame
	 * @param cause the cause of this event
	 */
	void threadSelected(FridaThread thread, FridaFrame frame, FridaCause cause);

	/**
	 * A module has been loaded by an process
	 * 
	 * @param process a handle to the process which loaded the module
	 * @param info the name of the module on the target
	 * @param index in-order index
	 * @param cause the cause of this event
	 */
	void moduleLoaded(FridaProcess process, FridaModuleInfo info, int index, FridaCause cause);

	/**
	 * A module has been loaded by an process
	 * 
	 * @param process a handle to the process which loaded the module
	 * @param info the name of the module on the target
	 * @param index in-order index
	 * @param cause the cause of this event
	 */
	void moduleReplaced(FridaProcess process, FridaModuleInfo info, int index, FridaCause cause);

	/**
	 * A module has been unloaded from an process
	 * 
	 * @param process a handle to the process which unloaded the module
	 * @param info the name of the module on the target
	 * @param index in-order index
	 * @param cause the cause of this event
	 */
	void moduleUnloaded(FridaProcess process, FridaModuleInfo info, int index, FridaCause cause);

	/**
	 * A module has been loaded by an process
	 * 
	 * @param process a handle to the process which loaded the module
	 * @param info the name of the region on the target
	 * @param index in-order index
	 * @param cause the cause of this event
	 */
	void regionAdded(FridaProcess process, FridaRegionInfo info, int index, FridaCause cause);

	/**
	 * A module has been loaded by an process
	 * 
	 * @param process a handle to the process which loaded the module
	 * @param info the name of the region on the target
	 * @param index in-order index
	 * @param cause the cause of this event
	 */
	void regionReplaced(FridaProcess process, FridaRegionInfo info, int index, FridaCause cause);

	/**
	 * A module has been unloaded from an process
	 * 
	 * @param process a handle to the process which unloaded the module
	 * @param info the name of the region on the target
	 * @param index in-order index
	 * @param cause the cause of this event
	 */
	void regionRemoved(FridaProcess process, FridaRegionInfo info, int index, FridaCause cause);

	/**
	 * @param output console output
	 * @param mask class of output
	 */
	void consoleOutput(String output, int mask);

	/**
	 * @param prompt for console output
	 */
	void promptChanged(String prompt);

}
