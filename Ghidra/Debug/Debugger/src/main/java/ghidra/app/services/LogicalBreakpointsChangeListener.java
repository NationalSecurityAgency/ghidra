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
package ghidra.app.services;

import java.util.Collection;

import ghidra.trace.model.breakpoint.TraceBreakpoint;

public interface LogicalBreakpointsChangeListener {
	default void breakpointAdded(LogicalBreakpoint added) {
	};

	default void breakpointsAdded(Collection<LogicalBreakpoint> added) {
		for (LogicalBreakpoint a : added) {
			breakpointAdded(a);
		}
	}

	default void breakpointUpdated(LogicalBreakpoint updated) {
	};

	default void breakpointsUpdated(Collection<LogicalBreakpoint> updated) {
		for (LogicalBreakpoint u : updated) {
			breakpointUpdated(u);
		}
	}

	default void breakpointRemoved(LogicalBreakpoint removed) {
	};

	default void breakpointsRemoved(Collection<LogicalBreakpoint> removed) {
		for (LogicalBreakpoint r : removed) {
			breakpointRemoved(r);
		}
	}

	default void locationAdded(TraceBreakpoint added) {
	}

	default void locationUpdated(TraceBreakpoint updated) {
	}

	default void locationRemoved(TraceBreakpoint removed) {
	}
}
