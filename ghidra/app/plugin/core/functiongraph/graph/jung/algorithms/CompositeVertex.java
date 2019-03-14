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
package ghidra.app.plugin.core.functiongraph.graph.jung.algorithms;

import java.util.*;

public class CompositeVertex<V, E> {
    private Collection<V> vertices;
    private Collection<E> internalEdges;
    private Collection<CompositeVertex<V, E>> nestedComposites;

    boolean doHashCode = true;
    int hashCode;

    @Override
    public int hashCode() {
        if (doHashCode) {
            int sa = 0;
            for (V v : collectSimpleVertices()) {
                final int hc = v.hashCode();
                final int rearranged = hc >> (32 - sa) | (hc << sa);
                hashCode ^= rearranged;
                sa += 11;
                while (sa > 31) {
                    sa -= 32;
                }
            }
            doHashCode = false;
        }
        return hashCode;
    }

    public CompositeVertex(V vertex) {
        this(Arrays.asList(vertex), new ArrayList<CompositeVertex<V, E>>(0));
    }

    public CompositeVertex(Collection<CompositeVertex<V, E>> nestedComposites) {
        this(new ArrayList<V>(0), nestedComposites);
    }

    public CompositeVertex(Collection<V> vertices,
            Collection<CompositeVertex<V, E>> nestedComposites) {
        this.vertices = Collections.unmodifiableCollection(vertices);
        this.internalEdges = new ArrayList<E>();
        this.nestedComposites = Collections.unmodifiableCollection(nestedComposites);
    }

    public void addInternalEdge(E edge) {
        internalEdges.add(edge);
    }

    public Set<V> collectSimpleVertices() {
        HashSet<V> result = new HashSet<V>();
        result.addAll(vertices);
        for (CompositeVertex<V, E> composite : nestedComposites) {
            Set<V> simpleVertices = composite.collectSimpleVertices();
            result.addAll(simpleVertices);
        }
        return result;
    }

    public Set<E> collectInternalEdges() {
        HashSet<E> result = new HashSet<E>();
        result.addAll(internalEdges);
        for (CompositeVertex<V, E> composite : nestedComposites) {
            Set<E> edges = composite.collectInternalEdges();
            result.addAll(edges);
        }
        return result;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("V: ");
        sb.append(collectSimpleVertices());
        sb.append(" E: ");
        sb.append(collectInternalEdges());
        return sb.toString();
    }
}
