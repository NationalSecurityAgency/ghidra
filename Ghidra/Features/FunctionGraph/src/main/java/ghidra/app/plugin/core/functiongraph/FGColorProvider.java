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
package ghidra.app.plugin.core.functiongraph;

import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.mvc.FunctionGraphVertexAttributes;
import ghidra.framework.options.SaveState;

import java.awt.Color;
import java.util.List;

public interface FGColorProvider {

	public boolean isUsingCustomColors();

	public List<Color> getRecentColors();

	public Color getMostRecentColor();

	public Color getColorFromUser(Color oldColor);

	public void savePluginColors(SaveState saveState);

	public void loadPluginColor(SaveState saveState);

	public void saveVertexColors(FGVertex vertex, FunctionGraphVertexAttributes settings);

	public void loadVertexColors(FGVertex vertex, FunctionGraphVertexAttributes settings);

	public void setVertexColor(FGVertex vertex, Color newColor);

	public void clearVertexColor(FGVertex vertex);
}
