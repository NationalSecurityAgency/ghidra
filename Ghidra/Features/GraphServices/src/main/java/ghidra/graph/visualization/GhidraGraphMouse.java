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
import org.jgrapht.Graph;
import org.jungrapht.visualization.VisualizationViewer;
import org.jungrapht.visualization.control.AbstractPopupGraphMousePlugin;
import org.jungrapht.visualization.control.DefaultGraphMouse;
import org.jungrapht.visualization.control.GraphElementAccessor;
import org.jungrapht.visualization.control.TransformSupport;
import org.jungrapht.visualization.layout.model.LayoutModel;
import org.jungrapht.visualization.selection.ShapePickSupport;

import java.awt.event.MouseEvent;
import java.awt.geom.Point2D;
import java.awt.geom.Rectangle2D;
import java.util.function.Consumer;
import java.util.function.Function;

import static org.jungrapht.visualization.VisualizationServer.PREFIX;

/**
 * An extension of the jungrapht DefaultGraphMouse. This class has references to
 * <ul>
 * <li>a {@link VisualizationViewer} (to access the Graph and LayoutModel)
 * <li>a {@link Consumer} of the Subgraph (to make new Graph displays)
 * <li>a {@link GraphDisplayListener} (to react to changes in node attributes)
 * <li>a {@code Function} to supply the id for a given vertex
 * <li>a {@code Function} to supply the name for a given vertex
 *
 */
public class GhidraGraphMouse<V, E> extends DefaultGraphMouse<V, E> {

    private static final String PICK_AREA_SIZE = PREFIX + "pickAreaSize";

    /**
     * holds the context for graph visualization
     */
    VisualizationViewer<V, E> viewer;
    /**
     * will accept a {@link Graph} and display it in a new tab or window
     */
    Consumer<Graph<V, E>> subgraphConsumer;

    /**
     * Accepts a vertex that was 'located'
     */
    Consumer<V> locatedVertexConsumer;
    /**
     * a listener for events, notably the event to request change of a vertex name
     */
    GraphDisplayListener graphDisplayListener;
    /**
     * supplies the id for a given vertex
     */
    Function<V, String> vertexIdFunction;
    /**
     * supplies the name for a given vertex
     */
    Function<V, String> vertexNameFunction;

    /**
     * create an instance
     * @param <V> vertex type
     * @param <E> edge type
     * @return a configured GhidraGraphMouseBuilder
     */
    public static <V, E> GhidraGraphMouseBuilder<V, E, ?, ?> builder() {
        return new GhidraGraphMouseBuilder<>();
    }

    /**
     * create an instance with default values
     */
    GhidraGraphMouse(GhidraGraphMouseBuilder<V, E, ?, ?> builder) {
        super(builder.vertexSelectionOnly(true));
        this.viewer = builder.viewer;
        this.subgraphConsumer = builder.subgraphConsumer;
        this.locatedVertexConsumer = builder.locatedVertexConsumer;
        this.graphDisplayListener = builder.graphDisplayListener;
        this.vertexIdFunction = builder.vertexIdFunction;
        this.vertexNameFunction = builder.vertexNameFunction;
    }

    /**
     * create the plugins, and load them
     */
    @Override
    public void loadPlugins() {
        add(new PopupPlugin());
        super.loadPlugins();
    }

    class PopupPlugin extends AbstractPopupGraphMousePlugin {

        SelectionFilterMenu<V, E> selectionFilterMenu;

        PopupPlugin() {
            this.selectionFilterMenu = new SelectionFilterMenu<>(viewer, subgraphConsumer);
        }

        @Override
        protected void handlePopup(MouseEvent e) {
            int pickSize = Integer.getInteger(PICK_AREA_SIZE, 4);
            Rectangle2D footprintRectangle =
                    new Rectangle2D.Float(
                            (float) e.getPoint().x - pickSize / 2f,
                            (float) e.getPoint().y - pickSize / 2f,
                            pickSize,
                            pickSize);

            LayoutModel<V> layoutModel = viewer.getVisualizationModel().getLayoutModel();
            GraphElementAccessor<V, E> pickSupport = viewer.getPickSupport();
            V pickedVertex;
            E pickedEdge = null;
            if (pickSupport instanceof ShapePickSupport) {
                ShapePickSupport<V, E> shapePickSupport =
                        (ShapePickSupport<V, E>) pickSupport;
                pickedVertex = shapePickSupport.getVertex(layoutModel, footprintRectangle);
                if (pickedVertex == null) {
                    pickedEdge = shapePickSupport.getEdge(layoutModel, footprintRectangle);
                }
            } else {
                TransformSupport<V, E> transformSupport = viewer.getTransformSupport();
                Point2D layoutPoint = transformSupport.inverseTransform(viewer, e.getPoint());
                pickedVertex = pickSupport.getVertex(layoutModel, layoutPoint.getX(), layoutPoint.getY());
                if (pickedVertex == null) {
                    pickedEdge = pickSupport.getEdge(layoutModel, layoutPoint.getX(), layoutPoint.getY());
                }
            }
            if (pickedVertex != null) {
                OnVertexSelectionMenu<V, E> menu =
                        new OnVertexSelectionMenu<>(viewer, graphDisplayListener,
                                vertexIdFunction, vertexNameFunction,
                                pickedVertex);
                menu.show(viewer.getComponent(), e.getX(), e.getY());
            } else if (pickedEdge != null) {
                OnEdgeSelectionMenu<V, E> menu =
                        new OnEdgeSelectionMenu<>(viewer, locatedVertexConsumer, pickedEdge);
                menu.show(viewer.getComponent(), e.getX(), e.getY());
            } else {
                selectionFilterMenu.show(viewer.getComponent(), e.getX(), e.getY());
            }
        }
    }
}


