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

import org.jgrapht.Graph;
import org.jgrapht.graph.AsSubgraph;
import org.jungrapht.visualization.VisualizationViewer;
import org.jungrapht.visualization.selection.MutableSelectedState;

import javax.swing.AbstractButton;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import java.awt.Component;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * {@code PopupMenu to offer vertex selection options. The user can
 * <ul>
 *     <li>hide vertices that are not selected.
 *     <li>hide vertices that are selected.
 *     <li>invert the selection.
 *     <li>'grow' the selected vertex set outwards following outgoing edges.
 *     <li>'grow' the selected vertex set inwards following incoming edges.
 *     <li>Create a new graph display consisting of the SubGraph of the selected vertices and their edges.
 */
public class SelectionFilterMenu<V, E> extends JPopupMenu {

    /**
     * holds the context of graph visualization
     */
    private final VisualizationViewer<V, E> visualizationViewer;

    /**
     * button to extend the selection outwards along outgoing edges
     * its a class member so that it can be re-enabled any time the popup is shown
     */
    AbstractButton growSelectionOutButton;

    /**
     * button to extend the selection inwards along incoming edges
     * its a class member so that it can be re-enabled any time the popup is shown
     */
    AbstractButton growSelectionInButton;

    /**
     * Create the popup menu and populate with buttons to:
     * <ul>
     *     <li>hide unselected vertices</li>
     *     <li>hide selected vertices</li>
     *     <li>Invert the selection</li>
     *     <li>Grow the selection outwards following outgoing edges</li>
     *     <li>Grow the selection inwards following incoming edges</li>
     *     <li>Display the selected vertices only in a new Graph display</li>
     * </ul>
     * @param visualizationViewer the {@link VisualizationViewer} that holds the context for graph visualization
     * @param subgraphConsumer a {@code Consumer} of a {@link Graph} to display in a new tab or window
     */
    public SelectionFilterMenu(VisualizationViewer<V, E> visualizationViewer,
                               Consumer<Graph<V, E>> subgraphConsumer) {
        this.visualizationViewer = visualizationViewer;
        MutableSelectedState<V> selectedVertexState = visualizationViewer.getSelectedVertexState();
        AbstractButton hideUnselectedToggleButton = new JCheckBox("Hide Unselected");
        AbstractButton hideSelectedToggleButton = new JCheckBox("Hide Selected");
        hideUnselectedToggleButton.addItemListener(evt ->
            manageVertexDisplay(hideSelectedToggleButton.isSelected(), hideUnselectedToggleButton.isSelected()));
        hideSelectedToggleButton.addItemListener(evt ->
                manageVertexDisplay(hideSelectedToggleButton.isSelected(), hideUnselectedToggleButton.isSelected()));
        AbstractButton toggleSelectionButton = new JCheckBox("Invert Selection");
        toggleSelectionButton.addActionListener(evt -> {
            Graph<V, E> graph = visualizationViewer.getVisualizationModel().getGraph();
            graph.vertexSet().forEach(v -> {
                        if (selectedVertexState.isSelected(v)) {
                            selectedVertexState.deselect(v);
                        } else {
                            selectedVertexState.select(v);
                        }
                    }
            );
            visualizationViewer.repaint();
        });
        this.growSelectionOutButton = new JButton("Grow Selection Outwards");
        this.growSelectionInButton = new JButton("Grow Selection Inwards");

        this.growSelectionOutButton.addActionListener(evt -> {
            growSelection(Graph::outgoingEdgesOf, Graph::getEdgeTarget);
            growSelectionInButton.setEnabled(canGrowSelection(Graph::incomingEdgesOf));
            growSelectionOutButton.setEnabled(canGrowSelection(Graph::outgoingEdgesOf));
                });

        this.growSelectionInButton.addActionListener(evt -> {
            growSelection(Graph::incomingEdgesOf, Graph::getEdgeSource);
            growSelectionInButton.setEnabled(canGrowSelection(Graph::incomingEdgesOf));
            growSelectionOutButton.setEnabled(canGrowSelection(Graph::outgoingEdgesOf));
        });

        JMenuItem subgraphDisplay = new JMenuItem("Display Selected As Graph");
        subgraphDisplay.addActionListener(evt -> {
            Graph<V, E> graph = visualizationViewer.getVisualizationModel().getGraph();
            subgraphConsumer.accept(new AsSubgraph<>(graph, selectedVertexState.getSelected()));
        });

        add(hideSelectedToggleButton);
        add(hideUnselectedToggleButton);
        add(toggleSelectionButton);
        add(growSelectionInButton);
        add(growSelectionOutButton);
        add(subgraphDisplay);
    }

    private boolean canGrowSelection(BiFunction<Graph<V, E>, V, Set<E>> growthFunction) {
        Graph<V, E> graph = visualizationViewer.getVisualizationModel().getGraph();
        Set<V> selectedVertices = visualizationViewer.getSelectedVertexState().getSelected();
        Set<E> selectedEdges = visualizationViewer.getSelectedEdgeState().getSelected();

        return selectedVertices.stream()
                .map(v -> growthFunction.apply(graph, v))
                .anyMatch(adjacentEdges -> !selectedEdges.containsAll(adjacentEdges));
    }

    /**
     * re-enaable the grow buttons in case the user cleared the selection in the graph display
     * @param invoker
     * @param x
     * @param y
     */
    @Override
    public void show(Component invoker, int x, int y) {
        this.growSelectionInButton.setEnabled(true);
        this.growSelectionOutButton.setEnabled(true);
        super.show(invoker, x, y);
    }

    /**
     * Use the supplied boolean flags to determine what vertices are shown:
     * <ul>
     *     <li>unselected vertices only</li>
     *     <li>selected vertices only</li>
     *     <li>both selected and unselected vertices are shown</li>
     *     <li>neither selected nor unselected vertices are shown</li>
     * </ul>
     * @param hideSelected a {@code boolean} flag to request hiding of selected vertices
     * @param hideUnselected a {@code boolean} flag to request hiding of unselected vertices
     */
    private void manageVertexDisplay(boolean hideSelected, boolean hideUnselected) {
        MutableSelectedState<V> selectedVertexState = visualizationViewer.getSelectedVertexState();
        if (hideSelected && hideUnselected) {
            visualizationViewer.getRenderContext()
                    .setVertexIncludePredicate(v -> false);
        } else if (hideSelected) {
            visualizationViewer.getRenderContext()
                    .setVertexIncludePredicate(Predicate.not(selectedVertexState::isSelected));
        } else if (hideUnselected) {
            visualizationViewer.getRenderContext()
                    .setVertexIncludePredicate(selectedVertexState::isSelected);
        } else {
            visualizationViewer.getRenderContext()
                    .setVertexIncludePredicate(v -> true);
        }
        visualizationViewer.repaint();
    }

    /**
     * select all vertices that are one hop away from any currently selected vertices
     * @param growthFunction either outgoing or incoming edges
     * @param neighborFunction either target or source vertices
     * @return true if the selection has changed
     */
    private boolean growSelection(BiFunction<Graph<V, E>, V, Set<E>> growthFunction,
                               BiFunction<Graph<V, E>, E, V> neighborFunction) {
        MutableSelectedState<V> selectedVertexState = visualizationViewer.getSelectedVertexState();

        Set<V> selectedVertices = new HashSet<>(selectedVertexState.getSelected());
        selectedVertexState.getSelected()
                .forEach(v -> selectedVertices.addAll(growSelection(v, growthFunction, neighborFunction)));
        return selectedVertexState.select(selectedVertices);
    }

    /**
     * select all vertices that are one hop away from the supplied vertex. The outgoing ar
     * incoming edges are not followed if they are already selected, or if they are hidden
     * by the edgeIncludePredicate. Likewise
     * @param vertex the vertex to start the selection from
     * @param growthFunction either outgoing or incoming edges
     * @param neighborFunction either target or source vertices
     * @return a collection of selected vertices
     */
    private Collection<V> growSelection(V vertex,
                                        BiFunction<Graph<V, E>, V, Set<E>> growthFunction,
                                        BiFunction<Graph<V, E>, E, V> neighborFunction) {
        Graph<V, E> graph = visualizationViewer.getVisualizationModel().getGraph();
        MutableSelectedState<V> selectedVertexState = visualizationViewer.getSelectedVertexState();
        MutableSelectedState<E> selectedEdgeState = visualizationViewer.getSelectedEdgeState();
        Predicate<E> edgeIncludePredicate = visualizationViewer.getRenderContext().getEdgeIncludePredicate();
        Predicate<V> vertexIncludePredicate = visualizationViewer.getRenderContext().getVertexIncludePredicate();
        // filter out edges we have already selected
        Set<E> connectingEdges = growthFunction.apply(graph, vertex)
                .stream().filter(e -> !selectedEdgeState.isSelected(e))
                .filter(edgeIncludePredicate)
                .collect(Collectors.toSet());
        visualizationViewer.getSelectedEdgeState().select(connectingEdges);
        // get the opposite endpoints for each edge and select them, if they are not already selected
        return connectingEdges.stream().map(e -> neighborFunction.apply(graph, e))
                .filter(v -> !selectedVertexState.isSelected(v))
                .filter(vertexIncludePredicate)
                .collect(Collectors.toSet());
    }
}
