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
package agent.dbgeng.dbgeng;

import java.util.ArrayList;
import java.util.List;

/**
 * A wrapper for {@code IDebugSystemObjects} and its newer variants.
 */
public interface DebugSystemObjects {

	DebugThreadId getEventThread();

	DebugProcessId getEventProcess();

	DebugSessionId getEventSystem();

	DebugThreadId getCurrentThreadId();

	void setCurrentThreadId(DebugThreadId id);

	DebugProcessId getCurrentProcessId();

	void setCurrentProcessId(DebugProcessId id);

	DebugSessionId getCurrentSystemId();

	void setCurrentSystemId(DebugSessionId id);

	int getNumberThreads();

	int getTotalNumberThreads(); // TODO: LargestProcess?

	/**
	 * Get the threads IDs by index from the current process
	 * 
	 * @param start the starting index
	 * @param count the number of threads
	 * @return the list of thread IDs
	 */
	List<DebugThreadId> getThreads(int start, int count);

	/**
	 * Get all thread IDs in the current process
	 * 
	 * @return the list of thread IDs
	 */
	default List<DebugThreadId> getThreads() {
		return getThreads(0, getNumberThreads());
	}

	DebugThreadId getThreadIdByHandle(long handle);

	DebugProcessId getProcessIdByHandle(long handle);

	int getNumberSystems();

	List<DebugSessionId> getSystems(int start, int count);

	default List<DebugSessionId> getSessions() {
		int numberSystems = getNumberSystems();
		if (numberSystems < 0) {
			return new ArrayList<DebugSessionId>();
		}
		return getSystems(0, numberSystems);
	}

	int getNumberProcesses();

	List<DebugProcessId> getProcesses(int start, int count);

	default List<DebugProcessId> getProcesses() {
		int numberProcesses = getNumberProcesses();
		if (numberProcesses < 0) {
			return new ArrayList<DebugProcessId>();
		}
		return getProcesses(0, numberProcesses);
	}

	int getCurrentThreadSystemId();

	int getCurrentProcessSystemId();

	DebugThreadId getThreadIdBySystemId(int systemId);

	DebugProcessId getProcessIdBySystemId(int systemId);

}
