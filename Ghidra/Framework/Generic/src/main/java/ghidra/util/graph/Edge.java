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

import ghidra.util.Msg;

/** An Edge joins a pair of vertices. 
 * The from and to vertex of an edge can not be changed.
 */
public final class Edge implements KeyedObject, Comparable<Edge>
{
  private final long key;
  private static final KeyedObjectFactory kof = KeyedObjectFactory.getInstance();
//  private static long nextKey = 0;
  private final Vertex from;
  private final Vertex to;

  /** @param from The from or parent vertex.
   * @param to The to or child vertex.
   */
  public Edge( Vertex from, Vertex to )
  {
      if( from == null || to == null )
      {
          Msg.error(this, "Bad edge");
      }
      this.key = getNextKey();
      this.from = from;
      this.to = to;
  }
  
  /** Returns next key **/
  private static synchronized long getNextKey() {
  	return kof.getNextAvailableKey();
  }

  /** Returns from vertex. */  
  public Vertex from()
  {
      return this.from;
  }

  /** Returns to vertex. */
  public Vertex to()
  {
      return this.to;
  }

  /** Returns the key of this edge. */
  public long key()
  {
      return this.key;
  }

  /** Compare one edge to another. Based on time of creation. */
  public int compareTo( Edge edge )
  {
      if( this.key() < edge.key() )
      {
          return -1;
      }
      else if( this.key() > edge.key() )
      {
          return +1;
      }
      return 0;
  }

  /** Overides equals method by comparing keys.
   */
  @Override
public boolean equals( Object obj )
  {
      if( obj instanceof Edge )
      {
    	  return key == ((Edge)obj).key();
      }
      return false;
  }
  
  @Override
	public int hashCode() {
	  return (int) key;
	}
}
