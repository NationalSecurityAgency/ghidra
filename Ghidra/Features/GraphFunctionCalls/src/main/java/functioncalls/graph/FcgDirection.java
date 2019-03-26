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
package functioncalls.graph;

/**
 * Represents whether a vertex is an incoming vertex (the start or from) on an edge, 
 * an outgoing vertex (the end or to) on an edge, or if it is both.
 */
public enum FcgDirection {

	// this order is from top to bottom: In -> In/Out -> Out
	IN, IN_AND_OUT, OUT;

	public boolean isSource() {
		return this == IN_AND_OUT;
	}

	public boolean isIn() {
		return this == IN;
	}

	public boolean isOut() {
		return this == OUT;
	}
}
