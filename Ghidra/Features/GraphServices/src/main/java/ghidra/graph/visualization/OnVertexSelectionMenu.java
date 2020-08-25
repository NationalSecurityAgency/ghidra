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

import ghidra.service.graph.GraphDisplayListener;
import org.apache.commons.lang3.StringUtils;
import org.jungrapht.visualization.VisualizationViewer;

import javax.swing.AbstractButton;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPopupMenu;
import java.util.function.Function;

/**
 * a Popup menu to allow actions relative to a particular vertex.
 * The popup appears on a right click over a vertex in the display.
 * The user can:
 * <ul>
 *     <li>select/deselect the vertex
 *     <li>rename the selected vertex (may modify the value in the listing)
 *     <li>re-label the selected vertex locally (affects only the local visual display)
 */
public class OnVertexSelectionMenu<V, E> extends JPopupMenu {

    public OnVertexSelectionMenu(VisualizationViewer<V, E> visualizationViewer,
                                 GraphDisplayListener graphDisplayListener,
                                 Function<V, String> vertexIdFunction,
                                 Function<V, String> vertexNameFunction,
                                 V vertex) {
        AbstractButton selectButton = new JMenuItem("Select");
        AbstractButton deselectButton = new JMenuItem("Deselect");
        AbstractButton renameAttributeButton = new JMenuItem("Rename vertex");
        renameAttributeButton.addActionListener(evt -> {
                    String newName = JOptionPane.showInputDialog("New Name Attribute");
                    if (!StringUtils.isEmpty(newName)) {
                        graphDisplayListener.updateVertexName(vertexIdFunction.apply(vertex),
                                vertexNameFunction.apply(vertex), newName);
                    }
                }
        );
        selectButton.addActionListener(evt -> {
            if (vertex != null) {
                visualizationViewer.getSelectedVertexState().select(vertex);
            }
        });
        deselectButton.addActionListener(evt -> {
            if (vertex != null) {
                visualizationViewer.getSelectedVertexState().deselect(vertex);
            }
        });
        add(visualizationViewer.getSelectedVertexState().isSelected(vertex) ? deselectButton : selectButton);
        add(renameAttributeButton);
    }
}
