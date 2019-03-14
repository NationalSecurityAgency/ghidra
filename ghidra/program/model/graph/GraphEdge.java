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
package ghidra.program.model.graph;

/**
 * Simple interface for a graph edge.
 */
public interface GraphEdge  {
    /**
     * Get the unique ID string tagged to this edge
     * @return edge ID
     */
    public String getID();
    /**
     * Set an attribute on this edge.
     *
     * NOTE: you must also define the attribute name on the graph
     *   display that this graph edge will be displayed on.
     *
     * @param attributeName the name of the attribute
     * @param value the value of the attribute
     */
    public void setAttribute(String attributeName, String value);
    /**
     * Get the value of an attribute.
     *
     * @param attributeName the name of the attribute
     *
     * @return the string value of the attribute
     */
    public String getAttribute(String attributeName);
}
