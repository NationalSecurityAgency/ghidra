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
package ghidra.base.graph;

import java.awt.Shape;

import javax.swing.JComponent;

import ghidra.graph.viewer.vertex.AbstractVisualVertex;
import ghidra.graph.viewer.vertex.VertexShapeProvider;

/**
 * A vertex that is a circle shape with a label below the circle to show the given text.
 */
public class CircleWithLabelVertex extends AbstractVisualVertex implements VertexShapeProvider {

	protected CircleWithLabelVertexShapeProvider shapeProvider;

	public CircleWithLabelVertex(String label) {
		this.shapeProvider = new CircleWithLabelVertexShapeProvider(label);
	}

	@Override
	public JComponent getComponent() {
		return shapeProvider.getComponent();
	}

	@Override
	public Shape getCompactShape() {
		return shapeProvider.getCompactShape();
	}

	@Override
	public Shape getFullShape() {
		return shapeProvider.getFullShape();
	}

	public String getName() {
		return shapeProvider.getName();
	}

	@Override
	public String toString() {
		return shapeProvider.getName();// + " @ " + level; // + " (" + System.identityHashCode(this) + ')';
	}

	@Override
	public void dispose() {
		// nothing to do
	}
}
