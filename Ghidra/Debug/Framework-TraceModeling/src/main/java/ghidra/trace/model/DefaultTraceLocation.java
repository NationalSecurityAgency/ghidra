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
package ghidra.trace.model;

import java.util.Objects;

import com.google.common.collect.Range;

import ghidra.program.model.address.Address;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.model.thread.TraceThread;

public class DefaultTraceLocation implements TraceLocation {
	private final Trace trace;
	private final TraceThread thread;
	private final Range<Long> lifespan;
	private final Address address;

	public DefaultTraceLocation(Trace trace, TraceThread thread, Range<Long> lifespan,
			Address address) {
		this.trace = trace;
		this.thread = thread;
		this.lifespan = lifespan;
		this.address = address;
	}

	@Override
	public Trace getTrace() {
		return trace;
	}

	@Override
	public TraceThread getThread() {
		return thread;
	}

	@Override
	public Range<Long> getLifespan() {
		return lifespan;
	}

	@Override
	public Address getAddress() {
		return address;
	}

	@Override
	public String toString() {
		return "TraceLocation<" + trace + ": " + lifespan + "," + address + ">";
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof DefaultTraceLocation)) {
			return false;
		}
		DefaultTraceLocation that = (DefaultTraceLocation) obj;
		if (this.trace != that.trace) {
			return false;
		}
		if (this.thread != that.thread) {
			return false;
		}
		if (!Objects.equals(this.address, that.address)) {
			return false;
		}
		if (!Objects.equals(this.lifespan, that.lifespan)) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		return Objects.hash(trace, thread, lifespan, address);
	}

	@Override
	public int compareTo(TraceLocation that) {
		if (this == that) {
			return 0;
		}
		int result;
		result = this.trace.getName().compareTo(that.getTrace().getName());
		if (result != 0) {
			return result;
		}
		result = this.thread.getName().compareTo(that.getThread().getName());
		if (result != 0) {
			return result;
		}
		result = DBTraceUtils.compareRanges(this.getLifespan(), that.getLifespan());
		if (result != 0) {
			return result;
		}
		result = this.address.compareTo(that.getAddress());
		if (result != 0) {
			return result;
		}
		return 0;
	}
}
