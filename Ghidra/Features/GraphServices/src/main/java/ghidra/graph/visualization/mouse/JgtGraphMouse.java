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
package ghidra.graph.visualization.mouse;

import java.awt.event.InputEvent;

import org.jungrapht.visualization.control.*;

import ghidra.graph.visualization.DefaultGraphDisplay;
import ghidra.service.graph.AttributedEdge;
import ghidra.service.graph.AttributedVertex;

/**
 * Pluggable graph mouse for jungrapht
 */
public class JgtGraphMouse extends DefaultGraphMouse<AttributedVertex, AttributedEdge> {

	private DefaultGraphDisplay graphDisplay;
	private boolean allowEdgeSelection;

	// TODO we should not need the graph display for any mouse plugins, but the API is net yet
	//      robust enough to communicate fully without it
	public JgtGraphMouse(DefaultGraphDisplay graphDisplay, boolean allowEdgeSelection) {
		super(DefaultGraphMouse.builder());
		this.graphDisplay = graphDisplay;
		this.allowEdgeSelection = allowEdgeSelection;
	}

	@Override
	public void loadPlugins() {

		//
		// Note: the order of these additions matters, as an event will flow to each plugin until
		//       it is handled.
		//

		// edge 
		add(new JgtEdgeNavigationPlugin<>(InputEvent.BUTTON1_DOWN_MASK));

		add(new JgtVertexFocusingPlugin<>(InputEvent.BUTTON1_DOWN_MASK, graphDisplay));

		//
		// JUNGRAPHT CHANGE 1,2
		//
		// Note: this code can go away when we can turn off the picking square
		add(allowEdgeSelection ? new SelectingGraphMousePlugin() : new VertexSelectingGraphMousePlugin<>());
		// add(new SelectingGraphMousePlugin<>());

		add(new RegionSelectingGraphMousePlugin<>());

		// the grab/pan feature
		add(TranslatingGraphMousePlugin.builder().translatingMask(InputEvent.BUTTON1_DOWN_MASK).build());

		// scaling
		add(new ScalingGraphMousePlugin());

		// cursor cleanup
		add(new JgtCursorRestoringPlugin<>());

		setPluginsLoaded();
	}

}
