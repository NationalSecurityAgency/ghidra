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
import org.jungrapht.visualization.control.DefaultGraphMouse;

import java.util.function.Consumer;
import java.util.function.Function;

import static org.jungrapht.visualization.VisualizationServer.PREFIX;

/**
 * An extension of the jungrapht DefaultGraphMouse.Builder. This class has references to
 * <ul>
 * <li>a {@link VisualizationViewer} (to access the Graph and LayoutModel)
 * <li>a {@link Consumer} of the Subgraph (to make new Graph displays)
 * <li>a {@link GraphDisplayListener} (to react to changes in node attributes)
 * <li>a {@code Function} to supply the id for a given vertex
 * <li>a {@code Function} to supply the name for a given vertex
 *
 */
public class GhidraGraphMouseBuilder<V, E, T extends GhidraGraphMouse<V, E>, B extends GhidraGraphMouseBuilder<V, E, T, B>>
        extends DefaultGraphMouse.Builder<V, E, T, B> {

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
     * accepts a 'located' vertex via a menu driven action
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

    public B self() {
        return (B) this;
    }

    public B viewer(VisualizationViewer<V, E> viewer) {
        this.viewer = viewer;
        return self();
    }

    public B subgraphConsumer(Consumer<Graph<V, E>> subgraphConsumer) {
        this.subgraphConsumer = subgraphConsumer;
        return self();
    }

    public B locatedVertexConsumer(Consumer<V> locatedVertexConsumer) {
        this.locatedVertexConsumer = locatedVertexConsumer;
        return self();
    }

    public B graphDisplayListener(GraphDisplayListener graphDisplayListener) {
        this.graphDisplayListener = graphDisplayListener;
        return self();
    }

    public B vertexIdFunction(Function<V, String> vertexIdFunction) {
        this.vertexIdFunction = vertexIdFunction;
        return self();
    }

    public B vertexNameFunction(Function<V, String> vertexNameFunction) {
        this.vertexNameFunction = vertexIdFunction;
        return self();
    }

    public T build() {
        return (T) new GhidraGraphMouse(this);
    }

    public static <V, E> GhidraGraphMouseBuilder<V, E, ?, ?> builder() {
        return new GhidraGraphMouseBuilder<>();
    }
}


