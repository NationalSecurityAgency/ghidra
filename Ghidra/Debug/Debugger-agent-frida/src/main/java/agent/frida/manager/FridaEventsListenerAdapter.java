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

public interface FridaEventsListenerAdapter extends FridaEventsListener {

	@Override
	public default void sessionAdded(FridaSession session, FridaCause cause) {
		// Extension point
	}

	@Override
	public default void sessionReplaced(FridaSession session, FridaCause cause) {
		// Extension point
	}

	@Override
	public default void sessionRemoved(String sessionId, FridaCause cause) {
		// Extension point
	}

	@Override
	public default void sessionSelected(FridaSession session, FridaCause cause) {
		// Extension point
	}

	@Override
	public default void processAdded(FridaProcess process, FridaCause cause) {
		// Extension point
	}

	@Override
	public default void processReplaced(FridaProcess process, FridaCause cause) {
		// Extension point
	}

	@Override
	public default void processRemoved(String processId, FridaCause cause) {
		// Extension point
	}

	@Override
	public default void processSelected(FridaProcess process, FridaCause cause) {
		// Extension point
	}

	@Override
	public default void processStarted(FridaProcess process, FridaCause cause) {
		// Extension point
	}

	@Override
	public default void processExited(FridaProcess process, FridaCause cause) {
		// Extension point
	}

	@Override
	public default void threadCreated(FridaThread thread, FridaCause cause) {
		// Extension point
	}

	@Override
	public default void threadReplaced(FridaThread thread, FridaCause cause) {
		// Extension point
	}

	@Override
	public default void threadStateChanged(FridaThread thread, FridaState state, FridaCause cause,
			FridaReason reason) {
		// Extension point
	}

	@Override
	public default void threadExited(FridaThread thread, FridaProcess process, FridaCause cause) {
		// Extension point

	}

	@Override
	public default void threadSelected(FridaThread thread, FridaFrame frame, FridaCause cause) {
		// Extension point
	}

	@Override
	public default void moduleLoaded(FridaProcess process, FridaModuleInfo info, int index,
			FridaCause cause) {
		// Extension point
	}

	@Override
	public default void moduleReplaced(FridaProcess process, FridaModuleInfo info, int index,
			FridaCause cause) {
		// Extension point
	}

	@Override
	public default void moduleUnloaded(FridaProcess process, FridaModuleInfo info, int index,
			FridaCause cause) {
		// Extension point
	}

	@Override
	public default void regionAdded(FridaProcess process, FridaRegionInfo info, int index,
			FridaCause cause) {
		// Extension point
	}

	@Override
	public default void regionReplaced(FridaProcess process, FridaRegionInfo info, int index,
			FridaCause cause) {
		// Extension point
	}

	@Override
	public default void regionRemoved(FridaProcess process, FridaRegionInfo info, int index,
			FridaCause cause) {
		// Extension point
	}

	@Override
	public default void consoleOutput(String output, int mask) {
		// Extension point
	}

	@Override
	public default void promptChanged(String prompt) {
		// Extension point
	}

}
