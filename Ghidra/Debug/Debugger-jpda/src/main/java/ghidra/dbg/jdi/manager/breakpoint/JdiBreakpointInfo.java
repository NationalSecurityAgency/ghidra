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
package ghidra.dbg.jdi.manager.breakpoint;

import java.util.*;

import com.sun.jdi.*;
import com.sun.jdi.request.*;

/**
 * Information about a JDI breakpoint
 * 
 * The contains the semantic processing for JDI breakpoint information. Mostly, it just stores the
 * information, but it also enumerates the locations of a breakpoint and generates the "effective"
 * breakpoints.
 * 
 * Note this is not a handle to the breakpoint. Rather, this is the captured information from some
 * event or request. If other commands have been executed since this information was gathered, the
 * information may be stale.
 */
public class JdiBreakpointInfo {

	private final EventRequest request;
	private final JdiBreakpointType type;

	private ObjectReference objectFilter;
	private ThreadReference threadFilter;
	private ReferenceType classFilter;
	private String filterPattern;
	private boolean excludePattern;

	public JdiBreakpointInfo(BreakpointRequest request) {
		this.request = request;
		this.type = JdiBreakpointType.BREAKPOINT;
	}

	public JdiBreakpointInfo(AccessWatchpointRequest request) {
		this.request = request;
		this.type = JdiBreakpointType.ACCESS_WATCHPOINT;
	}

	public JdiBreakpointInfo(ModificationWatchpointRequest request) {
		this.request = request;
		this.type = JdiBreakpointType.MODIFICATION_WATCHPOINT;
	}

	@Override
	public int hashCode() {
		return Objects.hash(request);
	}

	@Override
	public String toString() {
		return request.toString();
	}

	@Override
	public boolean equals(Object obj) {
		if (!((obj instanceof JdiBreakpointInfo))) {
			return false;
		}
		JdiBreakpointInfo that = (JdiBreakpointInfo) obj;
		if (this.request != that.request) {
			return false;
		}
		return true;
	}

	/**
	 * Get the type of breakpoint
	 * 
	 * @return the type
	 */
	public JdiBreakpointType getType() {
		return type;
	}

	/**
	 * Get the original request
	 * 
	 * @return the request
	 */
	public EventRequest getRequest() {
		return request;
	}

	public ObjectReference getObjectFilter() {
		return objectFilter;
	}

	public void setObjectFilter(ObjectReference objectFilter) {
		this.objectFilter = objectFilter;
	}

	public ThreadReference getThreadFilter() {
		return threadFilter;
	}

	public void setThreadFilter(ThreadReference threadFilter) {
		this.threadFilter = threadFilter;
	}

	public ReferenceType getClassFilter() {
		return classFilter;
	}

	public void setClassFilter(ReferenceType classFilter) {
		this.classFilter = classFilter;
	}

	public String getFilterPattern() {
		return filterPattern;
	}

	public void setFilterPattern(String filterPattern) {
		this.filterPattern = filterPattern;
	}

	public boolean isEnabled() {
		if (request instanceof BreakpointRequest) {
			return ((BreakpointRequest) request).isEnabled();
		}
		if (request instanceof WatchpointRequest) {
			return ((WatchpointRequest) request).isEnabled();
		}
		return false;
	}

	public void setEnabled(boolean b) {
		if (request instanceof BreakpointRequest) {
			BreakpointRequest breakpoint = (BreakpointRequest) request;
			if (b) {
				breakpoint.enable();
			}
			else {
				breakpoint.disable();
			}
		}
		if (request instanceof WatchpointRequest) {
			WatchpointRequest watchpoint = (WatchpointRequest) request;
			if (b) {
				watchpoint.enable();
			}
			else {
				watchpoint.disable();
			}
		}
	}

}
