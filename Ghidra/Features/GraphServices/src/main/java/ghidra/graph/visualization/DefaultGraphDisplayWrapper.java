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
package ghidra.graph.visualization;

import java.util.Collection;
import java.util.Set;

import docking.action.DockingActionIf;
import docking.widgets.EventTrigger;
import ghidra.service.graph.*;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link DefaultGraphDisplay} wrapper created to ensure all accesses to the delegate are on the
 * Swing thread.  This API is meant to be used concurrently.  We do not want to force clients to
 * have to understand when to use the Swing thread.  Thus, this class handles that for the clients.
 * Also, by having Swing accesses managed here, the {@link DefaultGraphDisplay} can assume that all
 * its work will be done on the Swing thread.
 */
public class DefaultGraphDisplayWrapper
		implements GraphDisplay, Comparable<DefaultGraphDisplayWrapper> {

	private DefaultGraphDisplay delegate;

	DefaultGraphDisplayWrapper(DefaultGraphDisplayProvider displayProvider, int id) {
		delegate = Swing.runNow(() -> new DefaultGraphDisplay(displayProvider, id));
	}

	void restoreDefaultState() {
		Swing.runNow(() -> delegate.restoreToDefaultSetOfActions());
	}

	boolean isDelegate(DefaultGraphDisplay other) {
		return other == delegate;
	}

	@Override
	public void setGraphDisplayListener(GraphDisplayListener listener) {
		Swing.runNow(() -> delegate.setGraphDisplayListener(listener));
	}

	@Override
	public void setFocusedVertex(AttributedVertex vertex, EventTrigger eventTrigger) {
		Swing.runNow(() -> delegate.setFocusedVertex(vertex));
	}

	@Override
	public AttributedGraph getGraph() {
		return Swing.runNow(() -> delegate.getGraph());
	}

	@Override
	public AttributedVertex getFocusedVertex() {
		return Swing.runNow(() -> delegate.getFocusedVertex());
	}

	@Override
	public void selectVertices(Set<AttributedVertex> vertexSet, EventTrigger eventTrigger) {
		Swing.runNow(() -> delegate.selectVertices(vertexSet, eventTrigger));
	}

	@Override
	public Set<AttributedVertex> getSelectedVertices() {
		return Swing.runNow(() -> delegate.getSelectedVertices());
	}

	@Override
	public void close() {
		Swing.runNow(() -> delegate.close());
	}

	@Override
	public void setGraph(AttributedGraph graph, GraphDisplayOptions options, String title,
			boolean append, TaskMonitor monitor) {
		Swing.runNow(() -> delegate.setGraph(graph, options, title, append, monitor));
	}

	@Override
	public void clear() {
		Swing.runNow(() -> delegate.clear());
	}

	@Override
	public void updateVertexName(AttributedVertex vertex, String newName) {
		Swing.runNow(() -> delegate.updateVertexName(vertex, newName));
	}

	@Override
	public String getGraphTitle() {
		return Swing.runNow(() -> delegate.getGraphTitle());
	}

	@Override
	public void addAction(DockingActionIf action) {
		Swing.runNow(() -> delegate.addAction(action));
	}

	@Override
	public Collection<DockingActionIf> getActions() {
		return Swing.runNow(() -> delegate.getActions());
	}

	@Override
	public int compareTo(DefaultGraphDisplayWrapper other) {
		// note: no need for call to Swing, assuming ID is immutable

		// larger/newer values are preferred so they should be first when sorting
		return -(delegate.getId() - other.delegate.getId());
	}
}
