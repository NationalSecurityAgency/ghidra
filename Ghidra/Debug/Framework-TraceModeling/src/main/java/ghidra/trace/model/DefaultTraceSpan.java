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

/**
 * NOTE: This is used to mark <trace,snap>; regardless of whether that snapshot is actually in the
 * database.... Cannot just use TraceSnapshot here.
 */
public class DefaultTraceSpan implements TraceSpan {

	private final Trace trace;
	private final Lifespan span;

	private final int hash;

	public DefaultTraceSpan(Trace trace, Lifespan span) {
		this.trace = trace;
		this.span = span;

		this.hash = Objects.hash(trace, span);
	}

	@Override
	public Trace getTrace() {
		return trace;
	}

	@Override
	public Lifespan getSpan() {
		return span;
	}

	@Override
	public String toString() {
		return "TraceSnap<" + trace + ": " + span + ">";
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof DefaultTraceSpan)) {
			return false;
		}
		DefaultTraceSpan that = (DefaultTraceSpan) obj;
		if (this.trace != that.trace) {
			return false;
		}
		if (!Objects.equals(this.span, that.span)) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		return hash;
	}

	@Override
	public int compareTo(TraceSpan that) {
		if (this == that) {
			return 0;
		}
		int result;
		result = this.trace.getName().compareTo(that.getTrace().getName());
		if (result != 0) {
			return result;
		}
		result = this.span.compareTo(that.getSpan());
		if (result != 0) {
			return result;
		}
		return 0;
	}
}
