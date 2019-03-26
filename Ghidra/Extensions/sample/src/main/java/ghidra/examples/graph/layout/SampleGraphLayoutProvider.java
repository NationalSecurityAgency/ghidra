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
package ghidra.examples.graph.layout;

import java.awt.geom.Point2D;
import java.util.Collection;

import javax.swing.Icon;

import edu.uci.ics.jung.algorithms.layout.Layout;
import ghidra.examples.graph.*;
import ghidra.graph.viewer.layout.AbstractLayoutProvider;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

/**
 * The layout provider for the {@link SampleGraphPlugin}.
 */
public abstract class SampleGraphLayoutProvider
		extends AbstractLayoutProvider<SampleVertex, SampleEdge, SampleGraph> {

	private static final Icon DEFAULT_ICON = ResourceManager.loadImage("images/color_swatch.png");

	@Override
	public abstract VisualGraphLayout<SampleVertex, SampleEdge> getLayout(SampleGraph g,
			TaskMonitor monitor) throws CancelledException;

	protected void initVertexLocations(SampleGraph g, Layout<SampleVertex, SampleEdge> layout) {
		Collection<SampleVertex> vertices = g.getVertices();
		for (SampleVertex v : vertices) {
			Point2D p = layout.apply(v);
			v.setLocation(p);
		}
	}

	// Note: each provider really should load its own icon so that the toolbar item can 
	//       signal to the user which layout is active
	@Override
	public Icon getActionIcon() {
		return DEFAULT_ICON;
	}
}
