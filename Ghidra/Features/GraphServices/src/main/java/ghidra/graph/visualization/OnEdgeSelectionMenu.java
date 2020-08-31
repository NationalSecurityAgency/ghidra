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
import org.jungrapht.visualization.VisualizationViewer;

import javax.swing.AbstractButton;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import java.util.Set;
import java.util.function.Consumer;

/**
 * a Popup menu to allow actions relative to a particular edge.
 * The popup appears on a right click over an edge in the display.
 * The user can select/deselect the edge. When the edge is selected,
 * its endpoints are also selected and the target endpoint is 'located'
 */
public class OnEdgeSelectionMenu<V, E> extends JPopupMenu {

    public OnEdgeSelectionMenu(VisualizationViewer<V, E> visualizationViewer,
                               Consumer<V> locatedVertexConsumer,
                               E edge) {
        Graph<V, E> graph = visualizationViewer.getVisualizationModel().getGraph();
        V source = graph.getEdgeSource(edge);
        V target = graph.getEdgeTarget(edge);
        AbstractButton selectButton = new JMenuItem("Select Edge");
        AbstractButton deselectButton = new JMenuItem("Deselect Edge");
        selectButton.addActionListener(evt -> {
                visualizationViewer.getSelectedEdgeState().select(edge);
                visualizationViewer.getSelectedVertexState().select(Set.of(source, target));
                locatedVertexConsumer.accept(target);
        });
        deselectButton.addActionListener(evt -> {
                visualizationViewer.getSelectedEdgeState().deselect(edge);
                visualizationViewer.getSelectedVertexState().deselect(Set.of(source, target));
        });
        add(visualizationViewer.getSelectedEdgeState().isSelected(edge) ? deselectButton : selectButton);
        AbstractButton locateSourceButton = new JMenuItem("Locate Edge Source");
        locateSourceButton.addActionListener(evt -> {
                locatedVertexConsumer.accept(source);
        });
        AbstractButton locateTargetButton = new JMenuItem("Locate Edge Target");
        locateTargetButton.addActionListener(evt -> {
            locatedVertexConsumer.accept(target);
        });
        add(locateSourceButton);
        add(locateTargetButton);
    }
}
