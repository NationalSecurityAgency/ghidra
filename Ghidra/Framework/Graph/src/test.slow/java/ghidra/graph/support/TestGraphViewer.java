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
package ghidra.graph.support;

import java.awt.Color;
import java.awt.Dimension;

import ghidra.graph.graphs.TestEdge;
import ghidra.graph.graphs.AbstractTestVertex;
import ghidra.graph.viewer.GraphViewer;

/**
 * A graph viewer used during testing (this can be deleted if no functionality is ever added).
 */
public class TestGraphViewer extends GraphViewer<AbstractTestVertex, TestEdge> {

	public TestGraphViewer(TestGraphLayout layout, Dimension size) {
		super(layout, size);
		setBackground(Color.WHITE);
	}

}
