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
package ghidra.graph.viewer;

import static org.junit.Assert.*;

import java.util.concurrent.atomic.*;

import javax.swing.*;

import org.junit.After;
import org.junit.Test;

import ghidra.graph.graphs.AbstractTestVertex;
import ghidra.graph.graphs.TestEdge;
import ghidra.graph.support.TestLayoutProvider;
import ghidra.graph.support.TestVisualGraph;
import ghidra.graph.viewer.vertex.VertexClickListener;

public class VisualGraphViewTest extends AbstractSimpleVisualGraphTest {

	private VisualGraphView<AbstractTestVertex, TestEdge, TestVisualGraph> view;
	private JDialog dialog = new JDialog((JFrame) null, "Test Satellite Dialog");

	@Override
	protected GraphComponent<AbstractTestVertex, TestEdge, TestVisualGraph> createGraphComponent(
			TestLayoutProvider layoutProvider) {

		view = new VisualGraphView<>();
		view.setGraph(graph);
		return view.getGraphComponent();
	}

	@Override
	@After
	public void tearDown() {
		close(dialog);
		super.tearDown();
	}

	@Test
	public void testShowHideUndockSatellite() {
		/*
		 	Tests the listener mechanism for the satellite behavior
		 */

		SpySatelliteListener listener = new SpySatelliteListener();
		view.setSatelliteListener(listener);

		assertTrue(view.isSatelliteVisible());
		assertTrue(view.isSatelliteDocked());

		runSwing(() -> view.setSatelliteDocked(false));
		assertTrue(listener.isSatelliteVisible());
		assertFalse(listener.isSatelliteDocked());
		assertTrue(view.isSatelliteVisible());
		assertFalse(view.isSatelliteDocked());

		runSwing(() -> view.setSatelliteDocked(true));
		assertTrue(listener.isSatelliteVisible());
		assertTrue(listener.isSatelliteDocked());
		assertTrue(view.isSatelliteVisible());
		assertTrue(view.isSatelliteDocked());

		runSwing(() -> view.setSatelliteVisible(false));
		assertFalse(listener.isSatelliteVisible());
		assertTrue(listener.isSatelliteDocked());
		assertFalse(view.isSatelliteVisible());
		assertTrue(view.isSatelliteDocked());

		runSwing(() -> view.setSatelliteVisible(true));
		assertTrue(listener.isSatelliteVisible());
		assertTrue(listener.isSatelliteDocked());
		assertTrue(view.isSatelliteVisible());
		assertTrue(view.isSatelliteDocked());
	}

	@Test
	public void testVertexClickListener_ConsumeEvents() {

		installMouseDebugger();

		AtomicInteger callCount = new AtomicInteger();
		AtomicReference<AbstractTestVertex> ref = new AtomicReference<>();
		VertexClickListener<AbstractTestVertex, TestEdge> listener = (v, info) -> {

			ref.set(v);
			callCount.incrementAndGet();
			return true;
		};

		view.setVertexClickListener(listener);

		setZoom(1.0);
		hideSatellite();
		AbstractTestVertex v = getAnyVertex();
		ensureVertexVisible(v);
		clickVertex(v, 10, 10, 2);

		assertEquals("Wrong vertex clicked", v, ref.get());
		assertEquals("More than one event for a double-click", 1, callCount.get());
	}

	// TODO Don't consume events

//==================================================================================================
// Private Methods
//==================================================================================================

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class SpySatelliteListener implements GraphSatelliteListener {

		private AtomicBoolean isDocked = new AtomicBoolean();
		private AtomicBoolean isVisible = new AtomicBoolean();

		@Override
		public void satelliteVisibilityChanged(boolean docked, boolean visible) {
			isDocked.set(docked);
			isVisible.set(visible);

			if (!docked) {
				// in new window?
				JComponent comp = view.getUndockedSatelliteComponent();
				if (visible) {
					dialog.getContentPane().add(comp);
				}
				else {
					dialog.getContentPane().remove(comp);
				}
				dialog.setVisible(visible);
			}
		}

		boolean isSatelliteDocked() {
			return isDocked.get();
		}

		boolean isSatelliteVisible() {
			return isVisible.get();
		}
	}
}
