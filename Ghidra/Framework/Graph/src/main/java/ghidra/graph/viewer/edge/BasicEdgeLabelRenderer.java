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
package ghidra.graph.viewer.edge;

import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.algorithms.layout.LayoutDecorator;
import edu.uci.ics.jung.visualization.RenderContext;
import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;
import ghidra.graph.viewer.layout.VisualGraphLayout;

/**
 * A class to override the default edge label placement.   This class is called a renderer because
 * the parent class is.  However, it is not a renderer in the sense that it's job is to paint
 * the contents, like in Java when you provide a cell rendering component, but rather, it uses
 * such a component.  Further, the job of this class is to position said component and then to 
 * have it paint its contents.
 * <p>
 * Normally we would just set our custom renderer on the {@link RenderContext} at construction 
 * time, like we do with the other rendering classes, but not such method is provided.
 */
public class BasicEdgeLabelRenderer<V extends VisualVertex, E extends VisualEdge<V>>
		extends edu.uci.ics.jung.visualization.renderers.BasicEdgeLabelRenderer<V, E> {

	@Override
	public void labelEdge(RenderContext<V, E> rc, Layout<V, E> layout, E e, String label) {

		// TODO delete this class

//		FGLayout functionGraphLayout = getFunctionGraphLayout(layout);
//		if (functionGraphLayout != null) {
//			EdgeLabel<FunctionGraphVertex, FunctionGraphEdge> overridingRenderer =
//				functionGraphLayout.getEdgeLabelRenderer();
//			if (overridingRenderer != null) {
//				overridingRenderer.labelEdge(rc, layout, e, label);
//				return;
//			}
//		}

		super.labelEdge(rc, layout, e, label);
	}

	private VisualGraphLayout<V, E> getFunctionGraphLayout(Layout<V, E> layout) {
		if (layout instanceof LayoutDecorator) {
			LayoutDecorator<V, E> layoutDecorator = (LayoutDecorator<V, E>) layout;
			layout = layoutDecorator.getDelegate();
		}

		if (layout instanceof VisualGraphLayout) {
			return (VisualGraphLayout<V, E>) layout;
		}
		return null;
	}
}
