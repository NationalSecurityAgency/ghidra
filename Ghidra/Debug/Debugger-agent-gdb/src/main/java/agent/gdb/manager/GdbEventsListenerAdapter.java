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

import java.util.Collection;

import agent.gdb.manager.breakpoint.GdbBreakpointInfo;
import agent.gdb.manager.reason.GdbReason;

/**
 * An adapter for {@link GdbEventsListener}
 * 
 * This provides an empty default implementation of each method.
 */
public interface GdbEventsListenerAdapter extends GdbEventsListener {
	@Override
	default void inferiorAdded(GdbInferior inferior, GdbCause cause) {
	}

	@Override
	default void inferiorRemoved(int inferiorId, GdbCause cause) {
	}

	@Override
	default void inferiorSelected(GdbInferior inferior, GdbCause cause) {
	}

	@Override
	default void inferiorStarted(GdbInferior inferior, GdbCause cause) {
	}

	@Override
	default void inferiorExited(GdbInferior inferior, GdbCause cause) {
	}

	@Override
	default void inferiorStateChanged(GdbInferior inf, Collection<GdbThread> threads,
			GdbState state, GdbThread thread, GdbCause cause, GdbReason reason) {
	}

	@Override
	default void threadCreated(GdbThread thread, GdbCause cause) {
	}

	@Override
	default void threadStateChanged(GdbThread thread, GdbState state, GdbCause cause,
			GdbReason reason) {
	}

	@Override
	default void threadExited(int threadId, GdbInferior inferior, GdbCause cause) {
	}

	@Override
	default void threadSelected(GdbThread thread, GdbStackFrame frame, GdbCause cause) {
	}

	@Override
	default void libraryLoaded(GdbInferior inferior, String name, GdbCause cause) {
	}

	@Override
	default void libraryUnloaded(GdbInferior inferior, String name, GdbCause cause) {
	}

	@Override
	default void breakpointCreated(GdbBreakpointInfo info, GdbCause cause) {
	}

	@Override
	default void breakpointModified(GdbBreakpointInfo newInfo, GdbBreakpointInfo oldInfo,
			GdbCause cause) {
	}

	@Override
	default void breakpointDeleted(GdbBreakpointInfo info, GdbCause cause) {
	}

	@Override
	default void memoryChanged(GdbInferior inferior, long addr, int len, GdbCause cause) {
	}

	@Override
	default void paramChanged(String param, String value, GdbCause cause) {
	}
}
