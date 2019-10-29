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
package ghidra.app.plugin.core.functiongraph.graph;

import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.graph.viewer.VisualEdge;
import ghidra.program.model.symbol.FlowType;

/**
 * This version of the {@link VisualEdge} adds a few methods.
 * 
 * <p>The {@link #setDefaultAlpha(double)} method was added here instead of the base interface, as it
 * was not needed any higher at the time of writing.  It can be pulled-up, but there is most 
 * likely a better pattern for specifying visual attributes of an edge.  If we find we need more
 * methods like this, then that is a good time for a refactor to change how we manipulate
 * rending attributes from various parts of the API (e.g., from the layouts and from animation
 * jobs).
 */
public interface FGEdge extends VisualEdge<FGVertex> {

	public FlowType getFlowType();

	public String getLabel();

	public void setLabel(String label);

	/**
	 * Set this edge's base alpha, which determines how much of the edge is visible/see through.
	 * 0 is completely transparent.
	 *   
	 * <P>This differs from {@link #setAlpha(double)} in that the latter is used for 
	 * temporary display effects.   This method is used to set the alpha value for the edge when
	 * it is not part of a temporary display effect.
	 * 
	 * @param alpha the alpha value
	 */
	public void setDefaultAlpha(double alpha);

	/**
	 * Set this edge's base alpha, which determines how much of the edge is visible/see through.
	 * 0 is completely transparent.
	 *   
	 * <P>This differs from {@link #getAlpha()} in that the latter is used for 
	 * temporary display effects.   This method is used to set the alpha value for the edge when
	 * it is not part of a temporary display effect.
	* 
	* @return the alpha value
	*/
	public double getDefaultAlpha();

	@SuppressWarnings("unchecked")
	// Suppressing warning on the return type; we know our class is the right type
	@Override
	public FGEdge cloneEdge(FGVertex start, FGVertex end);
}
