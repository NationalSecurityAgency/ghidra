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


/** The KeyedObjectFactory class is responsible for ensuring that no two
    vertices or edges have the same keys. One and only one instance of the 
    KeyedObjectFactory may exist. In addition to ensuring that all vertices 
    and edges contained within any graph have distinct keys, KeyedObjectFactory
    provides methods for obtaining the Object that a KeyedObject refers to. More 
    than one vertex may refer to the same object. The object a Vertex refers 
    to can not be changed. There is no method to return the vertex referring 
    to a specific object since in theory there can be a one-to-many 
    correspondence.
*/
public class KeyedObjectFactory
{
  private long keyCounter = 0;


  private KeyedObjectFactory()
  {
      //now is just a counter
  }

	/** The singleton instance of KeyedObjectFactory. */
  static public KeyedObjectFactory instance_ = new KeyedObjectFactory();

  /** Returns singleton instance of KeyedObjectFactory. */
  static public KeyedObjectFactory getInstance()
  {
      return instance_;
  }

  /** Gets returns the next available key. The keys are given out based on a
   *  one up counter. */
  synchronized long getNextAvailableKey()
  {
     return keyCounter++;
  }

}
