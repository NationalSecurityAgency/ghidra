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
package ghidra.util.graph;

import java.util.*;

/** 
 * Provides a depth first search service to directed graphs. 
 * Once a search has finished information about the search 
 * can be obtained.
 * 
 * 
 */
public class DepthFirstSearch
{
  private DirectedGraph graph;
  private List<Vertex>  seedsUsed;
  private Set<Vertex>   unseen;
  private Set<Vertex>   finished;
  private Stack<KeyedObject> pending;
  private LinkedList<Vertex>  finishListInReverseOrder;
  private List<Edge>  backEdges;
  private List<Edge>  treeEdges;
  //private List  forwardAndCrossEdges;

  /** 
   * Upon creation a depth first search of the given graph is performed.
   * 
   * @param graph The graph to search
   * @param initialSeeds The vertices used to start the search
   * @param getAdditionalSeedsIfNeeded If true, when searching from the initial
   * seeds does not find all vertices in the graph, additional start vertices will
   * be selected until every vertex is the graph has been found.
   * @param goForward Follow edges in their specifed direction
   * @param goBackward Follow edges in the opposite of their specified direction.
   */ 
  public DepthFirstSearch( DirectedGraph graph,
                           Vertex[]       initialSeeds,
                           boolean        getAdditionalSeedsIfNeeded,
                           boolean        goForward,
                           boolean        goBackward)
  {

      if( !goForward && !goBackward )
      {
          return;
      }
      this.graph = graph;
      seedsUsed = new ArrayList<Vertex>();
      unseen = graph.vertices().toSet();
      finished = new HashSet<Vertex>( graph.numVertices() );
      pending = new Stack<KeyedObject>();        //MyStack() for debugging


      finishListInReverseOrder = new LinkedList<Vertex>();
      backEdges = new ArrayList<Edge>( graph.numEdges()/5 );
      treeEdges = new ArrayList<Edge>( graph.numEdges()/5 );
      Vertex v;
      Edge e;
      Set<Edge> edges = null;
      Object o;
      Iterator<Edge> edgeIter;
      boolean done = true;

      Vertex[] seeds = initialSeeds;

    if( goForward && !goBackward )
    {
      do
      {
        for( int i=0; i< seeds.length; i++ )
        {
          v = seeds[i];
          if( isUnseen( v )  )
          {
              seedsUsed.add( v );
              pending.push( v );
              unseen.remove( v );
              while( !pending.isEmpty() )
              {
                  o = pending.peek();
                  if( o instanceof Vertex )
                  {
                      v = (Vertex)o;
                      edges = graph.getOutgoingEdges( v );
                      edgeIter = edges.iterator();
                      while( edgeIter.hasNext() )
                      {
                          pending.push( edgeIter.next() );
                      }
                      if( edges.size() == 0 )
                      {
                          finished.add( v );
                          finishListInReverseOrder.addFirst( v );
                          pending.pop();
                      }
                  }
                  else //it's an edge
                  {
                      e = (Edge)pending.pop();
                      v = e.to();
                      if( isUnseen( v ) )
                      {
                          pending.push( e );
                          pending.push( v );
                          treeEdges.add( e );
                          unseen.remove( v );
                      }
                      else if( isCompleted( v ) )
                      {
                          if( pending.peek() instanceof Vertex )
                          {
                             v = (Vertex)pending.pop();
                             finished.add( v );
                             finishListInReverseOrder.addFirst( v );
                          }
                      }
                      else //it is pending
                      {
                          backEdges.add( e );
                          if( pending.peek() instanceof Vertex )
                          {
                              v = (Vertex)pending.pop();
                              finished.add( v );
                              finishListInReverseOrder.addFirst( v );
                          }
                      }

                  }//peek at top of stack
              } //while stack is not empty
          }//if next seed is unseen
        }//while there are more seeds

        //If we need to search the whole graph (not just what is reachable from
        //the given seeds, then repeat the procedure using an iterator on list
        //derived from unseen rather than seeds. The iterator goes through
        //vertices in increasing key order.
        done = true;
        if( getAdditionalSeedsIfNeeded && !unseen.isEmpty() )
        {
          seeds = unseen.toArray(new Vertex[unseen.size()]);
          done = false;
        }
      }while( !done );
    }
    else if( !goForward && goBackward )
    {
      do
      {
        for( int i=0; i< seeds.length; i++ )
        {
          v = seeds[i];
          if( isUnseen( v )  )
          {
              seedsUsed.add( v );
              pending.push( v );
              unseen.remove( v );
              while( !pending.isEmpty() )
              {
                  o = pending.peek();
                  if( o instanceof Vertex )
                  {
                      v = (Vertex)o;
                      edges = graph.getIncomingEdges( v );
                      edgeIter = edges.iterator();
                      while( edgeIter.hasNext() )
                      {
                          pending.push( edgeIter.next() );
                      }
                      if( edges.size() == 0 )
                      {
                          finished.add( v );
                          finishListInReverseOrder.addFirst( v );
                          pending.pop();
                      }
                  }
                  else //it's an edge
                  {
                      e = (Edge)pending.pop();
                      v = e.from();
                      if( isUnseen( v ) )
                      {
                          pending.push( e );
                          pending.push( v );
                          treeEdges.add( e );
                          unseen.remove( v );
                      }
                      else if( isCompleted( v ) )
                      {
                          if( pending.peek() instanceof Vertex )
                          {
                             v = (Vertex)pending.pop();
                             finished.add( v );
                             finishListInReverseOrder.addFirst( v );
                          }
                      }
                      else //it is pending
                      {
                          backEdges.add( e );
                          if( pending.peek() instanceof Vertex )
                          {
                              v = (Vertex)pending.pop();
                              finished.add( v );
                              finishListInReverseOrder.addFirst( v );
                          }
                      }

                  }//peek at top of stack
              } //while stack is not empty
          }//if next seed is unseen
        }//while there are more seeds

        //If we need to search the whole graph (not just what is reachable from
        //the given seeds, then repeat the procedure using an iterator on list
        //derived from unseen rather than seeds. The iterator goes through
        //vertices in increasing key order.
        done = true;
        if( getAdditionalSeedsIfNeeded && !unseen.isEmpty() )
        {
          seeds = unseen.toArray(new Vertex[unseen.size()]);
          done = false;
        }
      }while( !done );

    }
    else// goForward && goBackward
    {
      do
      {
        for( int i=0; i< seeds.length; i++ )
        {
          v = seeds[i];
          if( isUnseen( v )  )
          {
              seedsUsed.add( v );
              pending.push( v );
              unseen.remove( v );
              while( !pending.isEmpty() )
              {
                  o = pending.peek();
                  if( o instanceof Vertex )
                  {
                      v = (Vertex)o;
                      edges = graph.getOutgoingEdges( v );
                      edges.addAll( graph.getIncomingEdges( v ) );
                      edgeIter = edges.iterator();
                      while( edgeIter.hasNext() )
                      {
                          pending.push( edgeIter.next() );
                      }
                      if( edges.size() == 0 )
                      {
                          finished.add( v );
                          finishListInReverseOrder.addFirst( v );
                          pending.pop();
                      }
                  }
                  else //its an edge
                  {
                      e = (Edge)pending.pop();
                      ListIterator<KeyedObject> li = pending.listIterator(pending.size());
                      v = null;
                      while( li.hasPrevious() && (v == null) )
                      {
                           o = li.previous();
                           if( o instanceof Vertex )
                           {
                               v = (Vertex)o;
                           }
                      }
                      if( isUnseen( v ) )
                      {
                          pending.push( e );
                          pending.push( v );
                          treeEdges.add( e );
                          unseen.remove( v );
                      }
                      else if( isCompleted( v ) )
                      {
                          if( pending.peek() instanceof Vertex )
                          {
                             v = (Vertex)pending.pop();
                             finished.add( v );
                             finishListInReverseOrder.addFirst( v );
                          }
                      }
                      else //it is pending
                      {
                          backEdges.add( e );
                          if( pending.peek() instanceof Vertex )
                          {
                              v = (Vertex)pending.pop();
                              finished.add( v );
                              finishListInReverseOrder.addFirst( v );
                          }
                      }

                  }//peek at top of stack
              } //while stack is not empty
          }//if next seed is unseen
        }//while there are more seeds

        //If we need to search the whole graph (not just what is reachable from
        //the given seeds, then repeat the procedure using an iterator on list
        //derived from unseen rather than seeds. The iterator goes through
        //vertices in increasing key order.
        done = true;
        if( getAdditionalSeedsIfNeeded && !unseen.isEmpty() )
        {
          seeds = unseen.toArray(new Vertex[unseen.size()]);
          done = false;
        }
      }while( !done );

    }
  }

  /** 
   * Return true if the vertex has not yet been discovered in the depth first
   * search.
   */
  public boolean isUnseen( Vertex v )
  {
      return unseen.contains( v );
  }

  /** 
   * Return true if the vertex has completed its role in the depth first
   * search.
   */
  public boolean isCompleted( Vertex v )
  {
      return finished.contains( v );
  }

  /** 
   * Return the back edges found in this depth first search. 
   */
  public Edge[] backEdges()
  {
      return backEdges.toArray(new Edge[backEdges.size()]);
  }

  /** 
   * Return the tree edges in this depth first search. 
   */
  public Edge[] treeEdges()
  {
      return treeEdges.toArray(new Edge[treeEdges.size()]);
  }

  /** 
   * Return true iff no back edges were found. 
   * 
   * Note that if the graph
   * is not completely explored the answer is only for the portion
   * of the graph expored.
   */
  public boolean isAcyclic()
  {
      return backEdges.isEmpty();
  }

  /** 
   * Return true iff the every edge is a tree edge. Will always be false
   * if the entire graph is not explored.
   */
  public boolean isTree()
  {
      return (treeEdges.size() == graph.numEdges() );
  }

  /** Returns a topological sort of the directed graph. 
   * Return the vertices in the explored 
   * portion of the graph with the following
   * property:
   * <ol>
   * <li>{@literal If the graph is acyclic then v[i] -> v[j] => i < j .}</li>
   * <li>If the graph contains cycles, then the above is true except when
   *     (v[i],v[j]) is a back edge.</li>
   * </ol>
   * 
   */
  public Vertex[] topologicalSort()
  {
      return finishListInReverseOrder.toArray(new Vertex[finishListInReverseOrder.size()]);
  }

  /** 
   * Return the seeds used in the depth first search. 
   **/
  List<Vertex> seedsUsed()
  {
      return seedsUsed;
  }

  /** 
   * Returns a spanning tree (in the form of a DirectedGraph). 
   * No claims that the spanning tree returned has any special 
   * properties.
   */
  public DirectedGraph spanningTree()
  {
      DirectedGraph g = new DirectedGraph( treeEdges.size() + 1, treeEdges.size() );
      Iterator<Edge> iter = treeEdges.iterator();
      while( iter.hasNext() )
      {
          g.add( iter.next() );
      }
      return g;
  }

}
