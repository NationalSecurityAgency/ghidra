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
package functioncalls.graph.job;

import java.awt.geom.Point2D;
import java.util.*;
import java.util.stream.Collectors;

import org.apache.commons.collections4.IterableUtils;
import org.apache.commons.collections4.map.LazyMap;

import edu.uci.ics.jung.algorithms.layout.Layout;
import functioncalls.graph.*;
import ghidra.graph.viewer.GraphViewer;
import util.CollectionUtils;

/**
 * A container to house all newly added vertices (those being arranged) and the sources, or 
 * 'from' vertices, of the new vertices.
 *   
 * <P>This offers exiting vertices and new vertices pre-sorted by position in the graph in
 * order to minimize edge crossings.  Specifically, the new vertices will be sorted 
 * by the level of the parent and then the x-value of the parent so that the
 * immediate parent level will be preferred, with the x-value dictating where to place 
 * the child so that we can minimize edge crossings.
 */
public class FcgExpandingVertexCollection {

	private Comparator<FcgVertex> sourceVertexComparator = this::compareVerticesByLayoutPosition;
	private Comparator<FcgVertex> addressComparator =
		(v1, v2) -> v1.getAddress().compareTo(v2.getAddress());

	private Map<FcgVertex, TreeSet<FcgVertex>> newVerticesBySource = LazyMap.lazyMap(
		new TreeMap<>(sourceVertexComparator), () -> new TreeSet<>(addressComparator));

	private GraphViewer<FcgVertex, FcgEdge> viewer;
	private FcgLevel parentLevel;
	private FcgLevel expandingLevel;
	private Set<FcgVertex> newVertices;
	private Set<FcgEdge> newEdges;
	private Set<FcgEdge> indirectEdges = Collections.emptySet();
	private boolean isIncoming;
	private Iterable<FcgVertex> sources;

	/**
	 * Constructor
	 * 
	 * @param sources all vertices that are the source of the expansion.  This will be either a
	 *        single vertex, clicked by the user, or all vertices of a source level being expanded
	 * @param parentLevel a.k.a, the source vertex level for the vertex that is the source of the 
	 * 		  new vertices
	 * @param expandingLevel the level of the new vertices
	 * @param newVertices the expanding vertices; those that are emanating from the parent
	 * @param newEdges the new edges being added as a result of adding the new vertices
	 * @param allParentLevelEdges all edges from all siblings of the parent vertex
	 * @param isIncoming true if the newly added vertices are callers of the source vertex; 
	 * 		  false if the newly added vertices are called by the source vertex
	 * @param viewer the viewer that is painting the graph.  This is needed to sort by layout
	 *        position
	 */
	public FcgExpandingVertexCollection(Iterable<FcgVertex> sources, FcgLevel parentLevel,
			FcgLevel expandingLevel, Set<FcgVertex> newVertices, Set<FcgEdge> newEdges,
			Set<FcgEdge> allParentLevelEdges, boolean isIncoming,
			GraphViewer<FcgVertex, FcgEdge> viewer) {

		this.sources = sources;
		this.parentLevel = parentLevel;
		this.newVertices = newVertices;
		this.newEdges = newEdges;
		this.isIncoming = isIncoming;
		this.viewer = viewer;
		this.expandingLevel = expandingLevel;

		// we need to use the parent edges to generate the siblings of the newly
		// added vertices, as well as to sort the new vertices amongst their siblings		
		for (FcgEdge e : allParentLevelEdges) {

			FcgVertex start = e.getStart();
			FcgVertex end = e.getEnd();
			FcgLevel startLevel = start.getLevel();
			FcgLevel endLevel = end.getLevel();

			if (expandingLevel.equals(startLevel)) {
				if (expandingLevel.equals(endLevel)) {
					// self-loop
					newVerticesBySource.get(start).add(end);
					newVerticesBySource.get(end).add(start);
				}
				else {
					newVerticesBySource.get(end).add(start);
				}
			}
			else {
				newVerticesBySource.get(start).add(end);
			}
		}
	}

	private int compareVerticesByLayoutPosition(FcgVertex v1, FcgVertex v2) {

		Layout<FcgVertex, FcgEdge> layout = viewer.getGraphLayout();

		FcgLevel l1 = v1.getLevel();
		FcgLevel l2 = v2.getLevel();
		int result = l1.compareTo(l2);
		if (result != 0) {

			//  prefer the parent level over all
			if (l1.equals(parentLevel)) {
				return -1;
			}
			else if (l2.equals(parentLevel)) {
				return 1;
			}

			return result;
		}

		Point2D p1 = layout.apply(v1);
		Point2D p2 = layout.apply(v2);
		return (int) (p1.getX() - p2.getX());
	}

	/**
	 * Returns all vertices at the given level
	 * 
	 * @param level the level to filter on
	 * @return the vertices
	 */
	public List<FcgVertex> getVerticesByLevel(FcgLevel level) {

		// note: these are sorted, since they are housed in a TreeMap
		Set<FcgVertex> existingVertices = newVerticesBySource.keySet();

		//@formatter:off		
		List<FcgVertex> verticesAtLevel = existingVertices
			.stream()
			.filter(v -> v.getLevel().equals(level))
			.collect(Collectors.toList())
			;					
		//@formatter:on

		return verticesAtLevel;
	}

	/**
	 * Returns all vertices that have just been added to the graph; those now being arranged
	 * 
	 * @return all vertices that have just been added to the graph; those now being arranged 
	 */
	public List<FcgVertex> getAllVerticesAtNewLevel() {

		// note: these are sorted, since they are housed in a TreeMap
		Set<FcgVertex> existingVertices = newVerticesBySource.keySet();

		//@formatter:off		
		LinkedHashSet<FcgVertex> sortedVertices = existingVertices
			.stream()
			.map(v -> newVerticesBySource.get(v))
	        .flatMap(set -> set.stream())
	        .filter(v -> v.getLevel().equals(expandingLevel)) // only include vertices not in graph
	        .collect(Collectors.toCollection(LinkedHashSet::new)) // unique, sorted by traversal from above
			;
		//@formatter:on

		return new ArrayList<>(sortedVertices);
	}

	/**
	 * Returns all vertices being added to the graph
	 * @return the vertices
	 */
	public Set<FcgVertex> getNewVertices() {
		return newVertices;
	}

	/**
	 * Returns all new edges being added to the graph
	 * @return the edges
	 */
	public Iterable<FcgEdge> getNewEdges() {
		return IterableUtils.chainedIterable(newEdges, indirectEdges);
	}

	/**
	 * Returns all edges that are being added to existing nodes
	 * @return the edges
	 */
	public Set<FcgEdge> getIndirectEdges() {
		return indirectEdges;
	}

	/**
	 * Returns the number of newly added edges
	 * @return the number of newly added edges
	 */
	public int getNewEdgeCount() {
		return newEdges.size() + indirectEdges.size();
	}

	/**
	 * Sets indirect edges--those edges that are not a direct link between the source 
	 * vertices and the newly added vertices
	 * @param indirectEdges the edges
	 */
	public void setIndirectEdges(Set<FcgEdge> indirectEdges) {
		this.indirectEdges = CollectionUtils.asSet(indirectEdges);
	}

	/**
	 * Returns the level of the newly added vertices, which is the level that is being expanded
	 * @return the level
	 */
	public FcgLevel getExpandingLevel() {
		return expandingLevel;
	}

	/**
	 * Returns the direction of the expansion
	 * @return the direction of the expansion
	 */
	public FcgDirection getExpandingDirection() {
		return expandingLevel.getDirection();
	}

	/**
	 * All vertices that are the source of the expansion
	 * @return the source vertices
	 */
	public Iterable<FcgVertex> getSources() {
		return sources;
	}

	/**
	 * Returns true if the newly added vertices are callers of the source vertex; false if
	 * the newly added vertices are called by the source vertex
	 * 
	 * @return true if the new vertices are incoming calls
	 */
	public boolean isIncoming() {
		return isIncoming;
	}
}
