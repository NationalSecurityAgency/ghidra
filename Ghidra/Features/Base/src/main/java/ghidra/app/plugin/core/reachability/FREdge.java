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
package ghidra.app.plugin.core.reachability;

import ghidra.graph.GEdge;

class FREdge implements GEdge<FRVertex> {

	private FRVertex start;
	private FRVertex end;

	FREdge(FRVertex start, FRVertex end) {
		this.start = start;
		this.end = end;
	}

	@Override
	public FRVertex getStart() {
		return start;
	}

	@Override
	public FRVertex getEnd() {
		return end;
	}

	@Override
	public String toString() {
		return start.toString() + " -> " + end.toString();
	}
}
