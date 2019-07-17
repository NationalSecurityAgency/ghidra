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

import ghidra.util.Msg;
import ghidra.util.datastruct.LongIntHashtable;
import ghidra.util.exception.NoValueException;

import java.util.*;

/** 
 * VertexSet is a container class for objects of type Vertex. It is
 * designed to be used in conjunction with EdgeSet as part of DirectedGraph.
 * 
 * 
 */
class VertexSet implements KeyIndexableSet<Vertex>
{
	  private final DirectedGraph parentGraph;
	  private long modificationNumber;
	  private int capacity;
	  private int nextIndex = 0;
	  private LongIntHashtable keyIndices;
	  private Edge [] firstOutgoingEdge;
	  private Edge [] firstIncomingEdge;
	  private Edge [] lastOutgoingEdge;
	  private Edge [] lastIncomingEdge;
	  private Vertex [] vertices;
	
	  /** 
	   * Constructor
	   * 
	   * @param parent The DirectedGraph this is a VertexSet of.
	   * @param capacity number of vertices that may be held without invoking grow()
	   */
	  public VertexSet( DirectedGraph parent, int capacity )
	  {
	      if( capacity < 10 ) capacity = 10;
	      this.parentGraph = parent;
	      this.modificationNumber = 0;
	      this.capacity = capacity;
	      keyIndices = new LongIntHashtable( capacity );
	      firstOutgoingEdge = new Edge[capacity];
	      firstIncomingEdge = new Edge[capacity];
	      lastOutgoingEdge = new Edge[capacity];
	      lastIncomingEdge = new Edge[capacity];
	      vertices = new Vertex[capacity];
	  }
	
	
	  /** 
	   * Return the internal index of the given vertex within this edge set.
	   * @return the internal index of o.
	   * @throws ClassCastException if the object is not a Vertex.
	   * @throws NoValueException if the KeyedObject is not in the VertexSet.
	   */
	  int index( Vertex v )
	  {
	      try{
	          return keyIndices.get( v.key() );
	      }catch( NoValueException exc ){
	          return -1;
	      }
	  }


	  /** 
	   * Adds the given vertex to the vertex set, if it does not already contain
	   * it.
	   * 
	   * @return true if and only if the vertex was sucessfully added.
	   */
	  public boolean add( Vertex v )
	  {
	      long key = v.key();
	      if( !keyIndices.contains( key ) )
	      {
	          if( nextIndex >= capacity )
	          {
	              grow();
	          }
	          keyIndices.put( key, nextIndex );
	          vertices[nextIndex++] = v;
	          modificationNumber++;
	          return true;
	      }
	      return false;
	  }
	
	  /** 
	   * Removes the given vertex from this vertex set if it contains it. 
	   * @return true if and only if the vertex was sucessfully removed.
	   */
	  public boolean remove( Vertex v )
	  {
		if (v == null) {
			return false;
		}
	    int index;
	    long key = v.key();
	    try
	    {
	      if( keyIndices.contains( key ) )
	      {
	          index = keyIndices.get( key );
	          while( firstOutgoingEdge[index] != null )
	          {
	                parentGraph.remove( firstOutgoingEdge[index] );
	          }
	          while( firstIncomingEdge[index] != null )
	          {
	              parentGraph.remove( firstIncomingEdge[index] );
	          }
	          keyIndices.remove( key );
	          vertices[index] = null;
	          modificationNumber++;
	          return true;
	      }
	    }
	    catch( NoValueException e )
	    {
	        return false;
	    }
	    return false;
	  }

	/** 
	 * Return The number of vertices in this VertexSet. 
	 */
  public int size()
  {
       return keyIndices.size();
  }

	/** 
	 * Return true iff the specified KeyedObject is contained in
	 * this VertexSet.
	 */
  public boolean contains( Vertex v )
  {
	  if (v == null) {
		  return false;
	  }
	  return keyIndices.contains( v.key() );
  }

	/** 
	 * Return the Vertex at the specified index. May be null. 
	 */
  private Vertex getByIndex( int index )
  {
      return vertices[index];
  }

  /** 
   * Return the number of sources.
   * This equals the number of vertices with no incoming
   * edges in the VertexSet. 
   */
  public int numSources()
  {
      int i, cnt = 0;

      for( i=0; i<nextIndex; i++ )
      {
          if( ( firstIncomingEdge[i] == null) && ( vertices[i] != null ) )
          {
              cnt++;
          }
      }
      return cnt;
  }

  /** 
   * Return the number of sinks.  
   * This equals the number of vertices with no outgoing
   * edges in the VertexSet. 
   */
  public int numSinks()
  {
      int i, cnt = 0;

      for( i=0; i<nextIndex; i++ )
      {
          if( ( firstOutgoingEdge[i] == null) && (vertices[i] != null) )
          {
              cnt++;
          }
      }
      return cnt;
  }

	/** 
	 * Return a Vertex[] containing all vertices in the VertexSet that
	 * have no incoming edges. If there are none an array of length 0 
	 * will be returned.
	 */
  Vertex [] getSources()
  {
      int i=0, n, j=0;

      n = numSources();
      Vertex [] answer = new Vertex[n];

      while( (j < n) && (i < nextIndex) )
      {
           if( (firstIncomingEdge[i] == null) && (vertices[i] != null) )
           {
               answer[j++] = vertices[i];
           }
           i++;
      }
      return answer;
  }

	/** 
	 * Return a Vertex[] containing all vertices in the VertexSet that
	 * have no outgoing edges. If there are none an array of length 0 
	 * will be returned.
	 */
  Vertex [] getSinks()
  {
      int i=0, n, j=0;

      n = numSinks();
      Vertex [] answer = new Vertex[n];

      while( (j < n) && (i < nextIndex) )
      {
           if( (firstOutgoingEdge[i] == null) && (vertices[i] != null) )
           {
               answer[j++] = vertices[i];
           }
           i++;
      }
      return answer;
  }

	/** 
	 * Get the first outgoing edge in the internal structures for this 
	 * VertexSet for the parent DirectedGraph.
	 */
  Edge getFirstOutgoingEdge( Vertex v )
  {
      //return firstOutgoingEdge[ index( v ) ];
      try{
          return firstOutgoingEdge[ keyIndices.get( v.key() ) ];
      }catch( NoValueException exc ){
         return null;
      }
  }

	/** 
	 * Get the last outgoing edge in the internal structures for this 
	 * VertexSet for the parent DirectedGraph.
	 */
  Edge getLastOutgoingEdge( Vertex v )
  {
      //return lastOutgoingEdge[ index( v ) ];
      try{

          Edge re = firstOutgoingEdge[ keyIndices.get( v.key() ) ];
          Edge e = re;
          EdgeSet es = parentGraph.edges();
          while( e != null )
          {
              re = e;
              e = es.getNextEdgeWithSameFrom( re );
          }
          return re;
      }catch( NoValueException exc ){
         return null;
      }
  }


	/** 
	 * Get the first incoming edge in the internal structures for this 
	 * VertexSet for the parent DirectedGraph.
	 */
  Edge getFirstIncomingEdge( Vertex v )
  {
      //return firstIncomingEdge[ index( v ) ];
      try{
          return firstIncomingEdge[ keyIndices.get( v.key() ) ];
      }catch( NoValueException exc ){
         return null;
      }
  }

	/** 
	 * Get the last incoming edge in the internal structures for this 
	 * VertexSet for the parent DirectedGraph.
	 */
  Edge getLastIncomingEdge( Vertex v )
  {
      //return lastIncomingEdge[ index( v ) ];
      try{
          Edge re = firstIncomingEdge[ keyIndices.get( v.key() ) ];
          Edge e = re;
          EdgeSet es = parentGraph.edges();
          while( e != null )
          {
              re = e;
              e = es.getNextEdgeWithSameTo( re );
          }
          return re;
      }catch( NoValueException exc ){
         return null;
      }
  }

	/** 
	 * Set the first outgoing edge of v to be e. 
	 * It is assumed that v has already been added to the graph. 
	 */
  void setFirstOutgoingEdge( Vertex v, Edge e )
  {
      try
      {
          firstOutgoingEdge[ index( v ) ] = e;
      }
      catch( ArrayIndexOutOfBoundsException exc )
      {
          Msg.error(this, "No Value Exception in setFirstOutgoingEdge()"
                            + "\tVertex: " + v.toString()
                            + "\tEdge: " + e.toString(), exc);
      }
  }

	/** 
	 * Set the last outgoing edge of v to be e. 
	 * It is assumed that v has already been added to the graph. 
	 */
  void setLastOutgoingEdge( Vertex v, Edge e )
  {
      try
      {
          lastOutgoingEdge[ index( v ) ] = e;
      }
      catch( ArrayIndexOutOfBoundsException exc )
      {
          Msg.error(this, "No Value Exception in setLastOutgoingEdge()"
                            + "\tVertex: " + v.toString()
                            + "\tEdge: " + e.toString(), exc);
      }
  }

	/** 
	 * Set the first incoming edge of v to be e. 
	 * It is assumed that v has already been added to the graph. 
	 */
  void setFirstIncomingEdge( Vertex v, Edge e )
  {
      try
      {
          firstIncomingEdge[ index( v ) ] = e;
      }
      catch( ArrayIndexOutOfBoundsException exc )
      {
          Msg.error(this, "No Value Exception in setFirstIncomingEdge()"
                            + "\tVertex: " + v.toString()
                            + "\tEdge: " + e.toString(), exc);
      }

  }

	/** 
	 * Set the last incoming edge of v to be e. 
	 * It is assumed that v has already been added to the graph. 
	 */
  void setLastIncomingEdge( Vertex v, Edge e )
  {
      try
      {
          lastIncomingEdge[ index( v ) ] = e;
      }
      catch( ArrayIndexOutOfBoundsException exc )
      {
          Msg.error(this, "No Value Exception in setLastIncomingEdge()"
                            + "\tVertex: " + v.toString()
                            + "\tEdge: " + e.toString(), exc);
      }
  }

	/** 
	 * Remove all of the vertices from this VertexSet without changing
	 * the capacity. Much faster than removing each vertex individually.
	 * The EdgeSet for this graph gets cleared first.
	 */
  void clear()
  {
      modificationNumber++;
      EdgeSet es = parentGraph.edges();
      if( es.size() > 0 )
      {
            es.clear();
      }
      if( size() > 0 )
       {
           nextIndex = 0;
           keyIndices.removeAll();
           for( int i = 0; i<capacity; i++ )
           {
               firstOutgoingEdge[i] = null;
               firstIncomingEdge[i] = null;
               lastOutgoingEdge[i] = null;
               lastIncomingEdge[i] = null;
               vertices[i] = null;
           }
       }
  }

  /*
   * @see ghidra.util.graph.KeyIndexableSet#getKeyedObject(long)
   */
	public Vertex getKeyedObject(long key) {
		if (keyIndices.contains(key))
			try {
				return vertices[keyIndices.get(key)];
			} catch (Exception e) {
				return null;
			}
		return null;
	}

//  void verbosePrint()
//  {
//      Err.debug(this, "Vertices:");
//      for( int i=0; i<capacity; i++ )
//      {
//          if( vertices[i] != null )
//          {
//              Err.debug(this,  vertices[i].name() + ", ");
//          }
//      }
//      Err.debug(this, "\n");
//  }

  /** 
   * Return the number of vertices this VertexSet may hold without growing.
   */
  public int capacity()
  {
      return this.capacity;
  }

	/** 
	 * Increases the capacity of the VertexSet so additional vertices
	 * can be added.
	 */
  void grow()
  {
      modificationNumber++;
      if( (keyIndices.size()*13)>(capacity*9) )
      {
          int newCapacity = (int)Math.round(keyIndices.size() * 1.7) + 7;

          Edge [] newFirstOutgoingEdge = new Edge[newCapacity];
          Edge [] newFirstIncomingEdge = new Edge[newCapacity];
          Edge [] newLastOutgoingEdge = new Edge[newCapacity];
          Edge [] newLastIncomingEdge = new Edge[newCapacity];
          Vertex [] newVertices = new Vertex[newCapacity];

          nextIndex=0;
          for( int i=0; i<capacity; i++ )
          {
              if( vertices[i] != null )
              {
                  newVertices[nextIndex] = vertices[i];
                  newFirstOutgoingEdge[nextIndex] = firstOutgoingEdge[i];
                  newFirstIncomingEdge[nextIndex] = firstIncomingEdge[i];
                  newLastOutgoingEdge[nextIndex] = lastOutgoingEdge[i];
                  newLastIncomingEdge[nextIndex] = lastIncomingEdge[i];
                  keyIndices.remove( vertices[i].key() );
                  keyIndices.put( vertices[i].key(), nextIndex);
                  nextIndex++;
              }
          }
          capacity = newCapacity;
          vertices = newVertices;
          firstOutgoingEdge = newFirstOutgoingEdge;
          firstIncomingEdge = newFirstIncomingEdge;
          lastOutgoingEdge = newLastOutgoingEdge;
          lastIncomingEdge = newLastIncomingEdge;
      }
      else// tighten up
      {
        tighten();
      }
  }

  /** 
   * Clean up the internal storage of the VertexSet. 
   */
  private void tighten()
  {
    modificationNumber++;
    // tighten up
    nextIndex = 0;
    for( int i=0; i<capacity; i++ )
    {
      if( vertices[i] != null )
      {
        if( i > nextIndex )
        {
          vertices[nextIndex] = vertices[i];
          firstOutgoingEdge[nextIndex] = firstOutgoingEdge[i];
          firstIncomingEdge[nextIndex] = firstIncomingEdge[i];
          lastOutgoingEdge[nextIndex] = lastOutgoingEdge[i];
          lastIncomingEdge[nextIndex] = lastIncomingEdge[i];
          keyIndices.remove( vertices[i].key() );
          keyIndices.put( vertices[i].key(), nextIndex);
          vertices[i] = null;
          firstOutgoingEdge[i] = null;
          firstIncomingEdge[i] = null;
          lastOutgoingEdge[i] = null;
          lastIncomingEdge[i] = null;
        }
        nextIndex++;
      }
    }
  }

	/** 
	 * Get the number of times this VertexSet has changed 
	 */
  public long getModificationNumber()
  {
      return this.modificationNumber;
  }

	/** 
	 * Return an iterator over all of the vertices in this VertexSet.
	 * The iterator becomes invalid and throws a ConcurrentModificationException
	 * if any changes are made to the VertexSet after the iterator is created.
	 */
  public GraphIterator<Vertex> iterator()
  {
      return new VertexSetIterator();
  }


	/** 
	 * Return the elements of this VertexSet as a java.util.Set. 
	 */
  public Set<Vertex> toSet()
  {
      Set<Vertex> vs = new HashSet<Vertex>( this.size() );
      GraphIterator<Vertex> i = this.iterator();
      while( i.hasNext() )
      {
          vs.add(i.next() );
      }
      return vs;
  }

	/** 
	 * Return the elements of this VertexSet as an Vertex[]. 
	 */
  public Vertex[] toArray()
  {
      Vertex[] theVertices = new Vertex[this.size()];
      int i=0, cnt = 0;
      int done = this.size();
      while( cnt < done )
      {
          if( vertices[i] != null )
          {
              theVertices[cnt++] = vertices[i];
          }
          i++;
      }
      return theVertices;
  }

	/** 
	 * Implements an Iterator for this VertexSet. 
	 */
	private class VertexSetIterator implements GraphIterator<Vertex>
	{
	    private int currentPosition;
	    private int nextPosition;
	    private long setModificationNumber;
	
		/** 
		 * Constructor 
		 */
	    public VertexSetIterator()     // VertexSet cvs)
	    {
	        currentPosition = -1;
	        nextPosition = -1;
	        this.setModificationNumber = getModificationNumber();
	        getNextPosition();
	    }
	
	    private void getNextPosition()
	    {
	        nextPosition++;
	        while( (nextPosition < capacity() ) && ( getByIndex(nextPosition) == null ))
	        {
	            nextPosition++;
	        }
	    }
	
		/** 
		 * Return true if there is another vertex in this iteration.
		 * @throws ConcurrentModificationException if the VertexSet is 
		 * modified by methods outside this iterator.
		 */
	    public boolean hasNext() throws ConcurrentModificationException
	    {
	        if( setModificationNumber != getModificationNumber() )
	        {
	            throw new ConcurrentModificationException("Set Modified");
	        }
	
	        if( nextPosition < capacity() )
	        {
	            return true;
	        }
	        return false;
	    }
	
		/** 
		 * Return the next Vertex in the iteration
		 */
	    public Vertex next() throws ConcurrentModificationException
	    {
	        if( setModificationNumber != getModificationNumber() )
	        {
	            throw new ConcurrentModificationException("Set Modified");
	        }
	        if( nextPosition < capacity() )
	        {
	            currentPosition = nextPosition;
	            getNextPosition();
	            return getByIndex(currentPosition);
	        }
	        throw new NoSuchElementException();
	    }
	
		/** 
		 * Remove the vertex returned by the most recent call to next(). 
		 */
	    public boolean remove() throws ConcurrentModificationException
	    {
	        boolean removed;
	        if( setModificationNumber != getModificationNumber() )
	        {
	            throw new ConcurrentModificationException("Set Modified");
	        }
	        removed = VertexSet.this.remove( getByIndex(currentPosition) );
	        setModificationNumber = getModificationNumber();
	        return removed;
	    }
	
	}

}

