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
package functioncalls.graph.layout;

import javax.swing.Icon;

import functioncalls.graph.*;
import ghidra.graph.viewer.layout.AbstractLayoutProvider;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

/**
 * A layout provider for the {@link BowTieLayout}
 */
public class BowTieLayoutProvider
		extends AbstractLayoutProvider<FcgVertex, FcgEdge, FunctionCallGraph> {

	public static final String NAME = "Bow Tie Layout";

	private static final Icon DEFAULT_ICON = ResourceManager.loadImage("images/color_swatch.png");

	@Override
	public VisualGraphLayout<FcgVertex, FcgEdge> getLayout(FunctionCallGraph graph,
			TaskMonitor monitor) throws CancelledException {

		BowTieLayout layout = new BowTieLayout(graph, NAME);
		initVertexLocations(graph, layout);
		return layout;
	}

	@Override
	public String getLayoutName() {
		return NAME;
	}

	@Override
	public Icon getActionIcon() {
		return DEFAULT_ICON;
	}
}
