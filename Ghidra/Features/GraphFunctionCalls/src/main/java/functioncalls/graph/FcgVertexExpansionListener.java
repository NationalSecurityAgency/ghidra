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
 * A listener to know when a vertex has been told to expand
 */
public interface FcgVertexExpansionListener {

	/**
	 * Show or hide those vertices that are on incoming edges to v
	 * 
	 * @param v the vertex
	 */
	public void toggleIncomingVertices(FcgVertex v);

	/**
	 * Show or hide those vertices that are on outgoing edges to v
	 * 
	 * @param v the vertex
	 */
	public void toggleOutgoingVertices(FcgVertex v);
}
