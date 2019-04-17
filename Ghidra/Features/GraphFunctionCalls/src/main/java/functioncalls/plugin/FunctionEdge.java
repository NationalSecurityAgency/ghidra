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
package functioncalls.plugin;

import java.util.Objects;

import ghidra.program.model.listing.Function;

/** 
 * An edge between two functions.  This edge is never added to the graph, but exists for us
 * to maintain relationships between functions outside of the visual graph.
 */
class FunctionEdge {

	private Function start;
	private Function end;

	FunctionEdge(Function start, Function end) {
		this.start = start;
		this.end = end;
	}

	Function getStart() {
		return start;
	}

	Function getEnd() {
		return end;
	}

	@Override
	public String toString() {
		return "[" + start + ", " + end + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((end == null) ? 0 : end.hashCode());
		result = prime * result + ((start == null) ? 0 : start.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}

		FunctionEdge other = (FunctionEdge) obj;
		if (!Objects.equals(end, other.end)) {
			return false;
		}

		if (!Objects.equals(start, other.start)) {
			return false;
		}
		return true;
	}

}
