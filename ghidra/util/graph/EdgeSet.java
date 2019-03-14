/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.util.exception.NoValueException;

import java.util.*;


/** Container class for a set of edges (ghidra.util.graph.Edge). 
 * 
 * 
 */
class EdgeSet implements KeyIndexableSet<Edge> {
  private final DirectedGraph parentGraph;
  private long modificationNumber;
  private int capacity;
  private int nextIndex;
  private AddableLongIntHashtable edgeIndices;
  private Edge [] edges;
  private Edge [] previousEdgeWithSameFrom;
  private Edge [] previousEdgeWithSameTo;
  private Edge [] nextEdgeWithSameFrom;
  private Edge [] nextEdgeWithSameTo;

/** Constructor
 * @param parent The DirectedGraph that this EdgeSet belongs to.
 * @param capacity The initial number of edges this edge set can have
 * without growing.
 */
  EdgeSet( DirectedGraph parent, int capacity)
  {
      if( capacity < 10 ) capacity = 10;
      this.parentGraph = parent;
      this.modificationNumber = 0;
      this.capacity = capacity;
      this.nextIndex = 0;
      edgeIndices = new AddableLongIntHashtable( capacity );
      edges = new Edge[capacity];
      previousEdgeWithSameFrom = new Edge[capacity];
      previousEdgeWithSameTo = new Edge[capacity];
      nextEdgeWithSameFrom = new Edge[capacity];
      nextEdgeWithSameTo = new Edge[capacity];
  }

  /** Returns the edge at the specified index in the internal arrays. */
  Edge getByIndex( int index )
  {
      return edges[index];
  }

  /** Removes an edge from this EdgeSet. Returns true if and only if the
   *   edge was in the EdgeSet and was sucessfully removed.
   */
  public boolean remove( Edge e )
  {
      if( e == null )
      {
          return false;
      }
      VertexSet vertices  = parentGraph.vertices();
      Edge oldNextEdgeWithSameFrom     = getNextEdgeWithSameFrom( e );
      Edge oldNextEdgeWithSameTo       = getNextEdgeWithSameTo( e );
      Edge oldPreviousEdgeWithSameFrom = getPreviousEdgeWithSameFrom( e);
      Edge oldPreviousEdgeWithSameTo   = getPreviousEdgeWithSameTo( e );
      Vertex from = e.from();
      Vertex to = e.to();
      Edge firstOutgoingEdgeOfFrom = vertices.getFirstOutgoingEdge( from );
      Edge firstIncomingEdgeOfTo   = vertices.getFirstIncomingEdge( to );
      Edge lastOutgoingEdgeOfFrom  = vertices.getLastOutgoingEdge( from );
      Edge lastIncomingEdgeOfTo    = vertices.getLastIncomingEdge( to );

      if( e.equals( firstOutgoingEdgeOfFrom ) )
      {
          vertices.setFirstOutgoingEdge( from, oldNextEdgeWithSameFrom );
      }

      if( e.equals( lastOutgoingEdgeOfFrom ) )
      {
          vertices.setLastOutgoingEdge( from, oldPreviousEdgeWithSameFrom );
      }

      if( e.equals( firstIncomingEdgeOfTo ) )
      {
          vertices.setFirstIncomingEdge( to, oldNextEdgeWithSameTo );
      }

      if( e.equals( lastIncomingEdgeOfTo ) )
      {
          vertices.setLastIncomingEdge( to, oldPreviousEdgeWithSameTo );
      }

      if( oldNextEdgeWithSameFrom != null )
      {
          setPreviousEdgeWithSameFrom(oldNextEdgeWithSameFrom, oldPreviousEdgeWithSameFrom);
      }

      if( oldPreviousEdgeWithSameFrom != null )
      {
          setNextEdgeWithSameFrom(oldPreviousEdgeWithSameFrom, oldNextEdgeWithSameFrom);
      }

      if( oldNextEdgeWithSameTo != null )
      {
          setPreviousEdgeWithSameTo(oldNextEdgeWithSameTo,oldPreviousEdgeWithSameTo);
      }

      if( oldPreviousEdgeWithSameTo != null )
      {
          setNextEdgeWithSameTo(oldPreviousEdgeWithSameTo, oldNextEdgeWithSameTo);
      }

      setPreviousEdgeWithSameFrom(e , null );
      setNextEdgeWithSameFrom( e, null );
      setPreviousEdgeWithSameTo( e, null );
      setNextEdgeWithSameTo( e, null );

      try{
          int index = edgeIndices.get( e.key() );
          edges[index] = null;
          edgeIndices.remove( e.key() );
          modificationNumber++;
          return true;
      }catch( NoValueException exc ){
          //do nothing
      }
      return false;
  }


  /** Adds an edge to the graph. If either endpoint is not in the graph add it.
   *   If the edge is already in the graph return false and do nothing. 
   *  @return true if and only if the edge was sucessfully added.
   */
  public boolean add( Edge e )
  {
      if( contains(e) )
      {
          return false;
      }
      else if( nextIndex >= capacity )
      {
          grow();
      }

      edges[nextIndex] = e;
      edgeIndices.add( e.key(), nextIndex++ );
      VertexSet vertices = parentGraph.vertices();
      Vertex from = e.from();
      Vertex to = e.to();
      if( !vertices.contains( from ) )
      {
          vertices.add( from );
      }
      if( !vertices.contains( to ) )
      {
          vertices.add( to );
      }

      Edge oldLastOutgoingEdge = vertices.getLastOutgoingEdge( from );
      if( oldLastOutgoingEdge == null )
      {
          vertices.setFirstOutgoingEdge( from, e );
          vertices.setLastOutgoingEdge( from, e );
      }
      else
      {
          vertices.setLastOutgoingEdge( from, e );
          setNextEdgeWithSameFrom( oldLastOutgoingEdge, e );
          setPreviousEdgeWithSameFrom( e, oldLastOutgoingEdge );
      }

      Edge oldLastIncomingEdge = vertices.getLastIncomingEdge( to );
      if( oldLastIncomingEdge == null )
      {
          vertices.setFirstIncomingEdge( to, e );
          vertices.setLastIncomingEdge( to, e );
      }
      else
      {
          vertices.setLastIncomingEdge( to, e );
          setNextEdgeWithSameTo( oldLastIncomingEdge, e );
          setPreviousEdgeWithSameTo( e, oldLastIncomingEdge );
      }
      modificationNumber++;
      return true;

  }

  /** Return true if and only if the edge is contained in this EdgeSet. */
  public boolean contains( Edge edge )
  {
	  return edgeIndices.contains( edge.key() );
  }

  /** Returns the internal index of the given edge within this edge set.
   *  Throws a class cast exception if the object is not an edge. */
  int index( Edge e )
  {
      try{
          return edgeIndices.get( e.key() );
      }catch( NoValueException exc ){
          return -1;
      }
  }

  /** Returns the next edge having the same 'from' if it exists. Otherwise
      returns null.
  */
  Edge getNextEdgeWithSameFrom( Edge e )
  {
      int indexOfEdge = index(e);
      if( indexOfEdge >= 0 )
      {
          return nextEdgeWithSameFrom[ indexOfEdge ];
      }
      return null;
  }

  /** Returns next edge having the same 'to' if it exists. Otherwise returns
      null.
  */
  Edge getNextEdgeWithSameTo( Edge e )
  {
      int indexOfEdge = index( e );
      if( indexOfEdge >= 0 )
      {
          return nextEdgeWithSameTo[ indexOfEdge ];
      }
      return null;
  }

  /** Returns the previous edge having the same 'from' if it exists. Otherwise
      returns null.
  */
  Edge getPreviousEdgeWithSameFrom( Edge e )
  {
      int indexOfEdge = index( e );
      if( indexOfEdge >= 0 )
      {
          return previousEdgeWithSameFrom[ indexOfEdge ];
      }
      return null;
  }

  /** Returns previous edge having the same 'to' if it exists. Otherwise returns
      null.
  */
  Edge getPreviousEdgeWithSameTo( Edge e )
  {
      int indexOfEdge = index( e );
      if( indexOfEdge >= 0 )
      {
          return previousEdgeWithSameTo[ indexOfEdge ];
      }
      return null;
  }

	/** Helper method for maintaining internal data structures. */
  private void setNextEdgeWithSameFrom(Edge e, Edge nextEdge)
  {
      nextEdgeWithSameFrom[ index( e ) ] = nextEdge;
  }
  
	/** Helper method for maintaining internal data structures. */
  private void setNextEdgeWithSameTo(Edge e, Edge nextEdge)
  {
      nextEdgeWithSameTo[ index( e ) ] = nextEdge;
  }


	/** Helper method for maintaining internal data structures. */
  private void setPreviousEdgeWithSameFrom(Edge e, Edge previousEdge)
  {
      previousEdgeWithSameFrom[ index( e ) ] = previousEdge;
  }


	/** Helper method for maintaining internal data structures. */
  private void setPreviousEdgeWithSameTo(Edge e, Edge previousEdge)
  {
      previousEdgeWithSameTo[ index( e ) ] = previousEdge;
  }


  /** Returns the current number of edges within this edge set. */
  public int size()
  {
      return this.edgeIndices.size();
  }

  /** Empties out the edge set while leaving the capacity alone. Much faster
      than removing the edges one by one.
  */
  public void clear()
  {
      if( size() > 0 )
      {
            edgeIndices.removeAll();
            for( int i=0; i< capacity; i++ )
            {
                edges[i] = null;
                previousEdgeWithSameFrom[i] = null;
                previousEdgeWithSameTo[i] = null;
                nextEdgeWithSameFrom[i] = null;
                nextEdgeWithSameTo[i] = null;
            }
      }
      nextIndex = 0;
      modificationNumber++;
  }

  /** Returns the number of edges this edge set can hold without growing. */
  public int capacity()
  {
      return this.capacity;
  }

  /** Either compacts the edge set by removing vacant positions if there are
      many or grows the edge set so that there is additional space.
  */
  void grow()
  {
      int newCapacity = (int)Math.round( this.size()* 1.7) + 7;
      nextIndex = 0;
      modificationNumber++;
      if( (this.size()*13) > (capacity*9) )
      {
          Edge [] newEdges = new Edge[newCapacity];
          Edge [] newPreviousEdgeWithSameFrom = new Edge[newCapacity];
          Edge [] newPreviousEdgeWithSameTo = new Edge[newCapacity];
          Edge [] newNextEdgeWithSameFrom = new Edge[newCapacity];
          Edge [] newNextEdgeWithSameTo = new Edge[newCapacity];

          for( int i=0; i<capacity; i++ )
          {
              if( edges[i] != null )
              {
                  newEdges[nextIndex] = edges[i];
                  newPreviousEdgeWithSameFrom[nextIndex] = previousEdgeWithSameFrom[i];
                  newPreviousEdgeWithSameTo[nextIndex] = previousEdgeWithSameTo[i];
                  newNextEdgeWithSameFrom[nextIndex] = nextEdgeWithSameFrom[i];
                  newNextEdgeWithSameTo[nextIndex] = nextEdgeWithSameTo[i];
                  this.edgeIndices.remove( edges[i].key());
                  this.edgeIndices.put( edges[i].key(), nextIndex );
                  nextIndex++;
              }
          }
          capacity = newCapacity;
          edges = newEdges;
          previousEdgeWithSameFrom = newPreviousEdgeWithSameFrom;
          previousEdgeWithSameTo = newPreviousEdgeWithSameTo;
          nextEdgeWithSameFrom = newNextEdgeWithSameFrom;
          nextEdgeWithSameTo = newNextEdgeWithSameTo;
      }
      else // just tighten
      {
        tighten();
      }
  }

  private void tighten()
  {
    nextIndex = 0;
    for( int i=0; i<capacity; i++ )
    {
      if( edges[i] != null )
      {
        if( i > nextIndex )
        {
          edges[nextIndex] = edges[i];
          previousEdgeWithSameFrom[nextIndex] = previousEdgeWithSameFrom[i];
          previousEdgeWithSameTo[nextIndex] = previousEdgeWithSameTo[i];
          nextEdgeWithSameFrom[nextIndex] = nextEdgeWithSameFrom[i];
          nextEdgeWithSameTo[nextIndex] = nextEdgeWithSameTo[i];
          edgeIndices.remove( edges[i].key());
          edgeIndices.put( edges[i].key(), nextIndex );
          edges[i] = null;
          previousEdgeWithSameFrom[i] = null;
          previousEdgeWithSameTo[i] = null;
          nextEdgeWithSameFrom[i] = null;
          nextEdgeWithSameTo[i] = null;
        }
        nextIndex++;
      }
    }
  }

  /** Returns an iterator for this EdgeSet. */
  public GraphIterator<Edge> iterator()
  {
      return new EdgeSetIterator();
  }

  /** Used to test if edges have been added or removed from this edge set. */
  public long getModificationNumber()
  {
     return this.modificationNumber;
  }
  
  /* (non-Javadoc)
   * @see ghidra.util.graph.KeyIndexableSet#getKeyedObject(long)
   */
  public Edge getKeyedObject(long key)
  {
	  if (edgeIndices.contains(key)) {
		  try {
			  return edges[edgeIndices.get(key)];
		  } catch (Exception e) {
			  return null;
		  }
	  }
	  return null; 
  }
  

//  /** Used for debugging. */
//  void verbosePrint()
//  {
//      Err.debug(this, "Edges:");
//      for( int i=0; i<capacity; i++ )
//      {
//          if( this.edges[i] != null )
//          {
//              Err.debug(this, "From: " + edges[i].from().name() + " To: " + edges[i].to().name());
//          }
//      }
//  }

  /** Get the edges in this EdgeSet as a java.util.Set. */
  public Set<Edge> toSet()
  {
      GraphIterator<Edge> i = this.iterator();
      Set<Edge> s = new HashSet<Edge>( this.size() );
      while( i.hasNext() )
      {
          s.add( i.next() );
      }
      return s;
  }

	/** @return array of Edges contained in this EdgeSet */
  public Edge[] toArray()
  {
      Edge[] theEdges = new Edge[this.size()];
      int i=0, cnt = 0;
      int done = this.size();
      while( cnt < done )
      {
          if( edges[i] != null )
          {
              theEdges[cnt++] = edges[i];
          }
          i++;
      }
      return theEdges;
  }



  /** EdgeSetIterator uses the hasNext()/next() paradigm. Throws
    a ConcurrentModificationException if any addition or deletions to
    the backing EdgeSet are made except through the iterator's own methods.
  */
  private class EdgeSetIterator implements GraphIterator<Edge>
  {
    private int currentPosition;
    private int nextPosition;
    private long edgeSetModificationNumber;

	/** Constructor */
    public EdgeSetIterator()
    {
        currentPosition = -1;
        nextPosition = -1;
        //CompactEdgeSet.edgeSet = (CompactEdgeSet)parentGraph.edges();
        this.edgeSetModificationNumber = getModificationNumber();
        getNextPosition();
    }

    private void getNextPosition()
    {
        nextPosition++;
        while( (nextPosition < capacity()) && ( edges[nextPosition] == null ))
        {
            nextPosition++;
        }
    }

    /** @return true if and only if a call to next() will return a valid edge. 
     * @throws ConcurrentModificationException 
     */
    public boolean hasNext() throws ConcurrentModificationException
    {
        if( edgeSetModificationNumber != getModificationNumber() )
        {
            throw new ConcurrentModificationException("Edge Set Modified");
        }
        if( nextPosition < capacity() )
        {
            return true;
        }
        return false;
    }

    /** @return the next edge.
     * @throws ConcurrentModificationException
     * @throws NoSuchElementException if there is no next edge.
     */
    public Edge next() throws ConcurrentModificationException
    {
        if( edgeSetModificationNumber != getModificationNumber() )
        {
            throw new ConcurrentModificationException("Edge Set Modified");
        }
        if( nextPosition < capacity() )
        {
            currentPosition = nextPosition;
            getNextPosition();
            return edges[currentPosition];
        }
        throw new NoSuchElementException();
    }

    /** Removes the edge returned by the most recent call to next(). */
    public boolean remove() throws ConcurrentModificationException
    {
        boolean removed;
        if( edgeSetModificationNumber != getModificationNumber() )
        {
            throw new ConcurrentModificationException("Edge Set Modified");
        }
        removed = EdgeSet.this.remove( edges[currentPosition] );
        edgeSetModificationNumber = getModificationNumber();
        return removed;
    }

}

}

