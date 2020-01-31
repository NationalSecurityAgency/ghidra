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
package ghidra.graph;

import java.awt.Component;
import java.awt.event.MouseEvent;
import java.util.*;

import docking.*;
import edu.uci.ics.jung.visualization.VisualizationViewer;
import edu.uci.ics.jung.visualization.picking.PickedState;
import ghidra.framework.options.SaveState;
import ghidra.graph.featurette.VgSatelliteFeaturette;
import ghidra.graph.featurette.VisualGraphFeaturette;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.actions.*;
import ghidra.graph.viewer.event.mouse.VertexMouseInfo;

/**
 * A base component provider for displaying {@link VisualGraph}s
 * 
 * <p>This class will provide many optional sub-features, enabled as desired by calling the
 * various <code>addXyzFeature()</code> methods.  
 * 
 * <p>Implementation Notes:   to get full functionality, you must:
 * <ul>
 *  <li>Have your plugin call {@link #readConfigState(SaveState)} and 
 *  {@link #writeConfigState(SaveState)} to save user settings.
 *  </li>
 *  <li>Enable features you desire after calling your {@link #addToTool()} method.
 *  </li>
 * </ul>
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 * @param <G> the graph type
 */
//@formatter:off
public abstract class VisualGraphComponentProvider<V extends VisualVertex, 
												   E extends VisualEdge<V>, 
												   G extends VisualGraph<V, E>> 
	extends ComponentProvider {
//@formatter:on

	// private static final String DISPLAY_POPUPS = "DISPLAY_POPUPS";

	private List<VisualGraphFeaturette<V, E, G>> subFeatures = new ArrayList<>();

	protected VisualGraphComponentProvider(Tool tool, String name, String owner) {
		super(tool, name, owner);
	}

	protected VisualGraphComponentProvider(Tool tool, String name, String owner,
			Class<?> contextType) {
		super(tool, name, owner, contextType);
	}

	/**
	 * You must return your graph view from this method
	 * @return your graph view
	 */
	public abstract VisualGraphView<V, E, G> getView();

	@Override
	public void componentHidden() {
		subFeatures.forEach(f -> f.providerClosed(this));
	}

	@Override
	public void componentShown() {
		subFeatures.forEach(f -> f.providerOpened(this));
	}

	/**
	 * Returns true if the satellite is showing, whether in the graph or undocked
	 * @return true if the satellite is showing, whether in the graph or undocked
	 */
	public boolean isSatelliteShowing() {
		GraphComponent<V, E, G> graphComponent = getView().getGraphComponent();
		return graphComponent.isSatelliteShowing();
	}

	/**
	 * Returns true if the satellite is embedded in the graph view, whether it is showing or not
	 * @return true if the satellite is embedded in the graph view, whether it is showing or not
	 */
	public boolean isSatelliteDocked() {
		return getView().isSatelliteDocked();
	}

	public Set<V> getSelectedVertices() {
		VisualGraphView<V, E, G> view = getView();
		VisualizationViewer<V, E> viewer = view.getPrimaryGraphViewer();
		PickedState<V> pickedState = viewer.getPickedVertexState();
		return pickedState.getPicked();
	}

	protected ComponentProvider getSatelliteProvider() {
		VgSatelliteFeaturette<V, E, G> feature = getSatelliteFeature();
		if (feature == null) {
			return null;
		}
		return feature.getSatelliteProvider();
	}

	private VgSatelliteFeaturette<V, E, G> getSatelliteFeature() {
		for (VisualGraphFeaturette<V, E, G> feature : subFeatures) {
			if (feature instanceof VgSatelliteFeaturette) {
				return (VgSatelliteFeaturette<V, E, G>) feature;
			}
		}
		return null;
	}

//==================================================================================================
// Featurette Methods
//==================================================================================================	

	/**
	 * Adds the satellite viewer functionality to this provider
	 */
	protected void addSatelliteFeature() {
		VgSatelliteFeaturette<V, E, G> satelliteFeature = new VgSatelliteFeaturette<>();
		satelliteFeature.init(this);
		subFeatures.add(satelliteFeature);
	}

	/*
	 
	 Features to provide
	 
		Actions
			-change layout
			-re-layout
			-disable popups
		
		Snapshots
		
		
		Save State
			-selected layout
			-satellite dock/vis state
			
		
		Save image
		
		Export graph:
			-xml?
			-dot
			-gephi?
			
		Undo/redo for graph operations (delete; group/ungroup; move)
			-rapid pressing will shortcut items
			-undo/redo allows us to prune nodes 
				--how to maintain old nodes/edges?  (FilteringVisualGraph)	
	
	*/

//==================================================================================================
// Provider Methods
//==================================================================================================	

	/**
	 * To be called at the end of this provider's lifecycle
	 */
	public void dispose() {
		subFeatures.forEach(f -> f.remove());
		subFeatures.clear();
	}

	/**
	 * Writes this providers saveable state to the given state object
	 * 
	 * @param saveState the state object into which state is to be written
	 */
	public void writeConfigState(SaveState saveState) {
		subFeatures.forEach(f -> f.writeConfigState(saveState));
	}

	/**
	 * Reads previously saved state from the given state object
	 * 
	 * @param saveState the state object that may contain state information for this provider
	 */
	public void readConfigState(SaveState saveState) {
		subFeatures.forEach(f -> f.readConfigState(saveState));
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {

		if (event == null) {
			VisualGraphView<V, E, G> view = getView();
			V v = view.getFocusedVertex();
			if (v != null) {
				return new VgVertexContext<>(this, v);
			}
			return new VgActionContext(this);
		}

		V v = getVertexUnderMouse(event);
		if (v != null) {
			return new VgVertexContext<>(this, v);
		}

		Component c = event.getComponent();
		if (getView().isSatelliteComponent(c)) {
			return new VgSatelliteContext(this);
		}

		return new VgActionContext(this, c);
	}

	private V getVertexUnderMouse(MouseEvent event) {

		Object source = event.getSource();
		GraphViewer<V, E> viewer = getPrimaryGraphViewer(source);
		if (viewer == null) {
			return null;
		}

		VertexMouseInfo<V, E> info =
			GraphViewerUtils.convertMouseEventToVertexMouseEvent(viewer, event);
		if (info == null) {
			return null;
		}

		V vertex = info.getVertex();
		return vertex;
	}

	private GraphViewer<V, E> getPrimaryGraphViewer(Object source) {
		GraphViewer<V, E> primaryGraphViewer = getView().getPrimaryGraphViewer();
		if (source == primaryGraphViewer) {
			return primaryGraphViewer;
		}
		return null;
	}

}
