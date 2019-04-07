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
package ghidra.util.graph.attributes;

import ghidra.util.Msg;
import ghidra.util.graph.KeyIndexableSet;
import ghidra.util.graph.KeyedObject;

import java.util.Enumeration;
import java.util.Hashtable;

/** Class which creates and keeps track of attributes defined 
 * for a single KeyIndexableSet.
 */
public class AttributeManager<T extends KeyedObject>
{
  private KeyIndexableSet<T> attributedSet;
  private Hashtable<String, Attribute<T>> definedAttributes;

  /** Use this String as the attributeType to create an IntegerAttribute. */
  public static final String INTEGER_TYPE = "INTEGER_TYPE";
  /** Use this String as the attributeType to create an LongAttribute. */
  public static final String LONG_TYPE = "LONG_TYPE";
  /** Use this String as the attributeType to create an DoubleAttribute. */
  public static final String DOUBLE_TYPE = "DOUBLE_TYPE";
  /** Use this String as the attributeType to create an StringAttribute. */
  public static final String STRING_TYPE = "STRING_TYPE";
  /** Use this String as the attributeType to create an ObjectAttribute. */
  public static final String OBJECT_TYPE = "OBJECT_TYPE";

	/** Constructor.
	 * @param attributedSet The KeyIndexableSet whose Attributes this
	 * AttributeManager manages.
	 */
  public AttributeManager(KeyIndexableSet<T> attributedSet)
  {
      this.attributedSet = attributedSet;
      definedAttributes = new Hashtable<String, Attribute<T>>();
  }

	/** Create a new attribute.
	 * @param attributeName The name used to identify this Attribute.
	 * @param attributeType The type of Attribute to construct. Public static
	 * Strings have been defined for the various choices.
	 */
  public Attribute<T> createAttribute( String attributeName, String attributeType)
  {
       Attribute<T> newAttribute;
//       if( definedAttributes.containsKey( attributeName ) )
//       {
//           Err.info(this, "Creating new attribute using same name as old attribute.");
//           Err.info(this, "Earlier attribute is now permanently destroyed.");
//       }
       if( attributeType.equals( INTEGER_TYPE ) )
       {
          newAttribute = new IntegerAttribute<T>( attributeName, attributedSet );
          definedAttributes.put( attributeName, newAttribute );
       }
       else if( attributeType.equals( LONG_TYPE ) )
       {
          newAttribute = new LongAttribute<T>( attributeName, attributedSet );
          definedAttributes.put( attributeName, newAttribute );
       }
       else if( attributeType.equals( DOUBLE_TYPE ) )
       {
          newAttribute = new DoubleAttribute<T>( attributeName, attributedSet );
          definedAttributes.put( attributeName, newAttribute );
       }
       else if( attributeType.equals( STRING_TYPE ) )
       {
          newAttribute = new StringAttribute<T>( attributeName, attributedSet );
          definedAttributes.put( attributeName, newAttribute );
       }
       else if( attributeType.equals( OBJECT_TYPE ) )
       {
          newAttribute = new ObjectAttribute<T>( attributeName, attributedSet );
          definedAttributes.put( attributeName, newAttribute );
       }
       else
       {
          Msg.warn(this, "Unknown attribute type. New Attribute is null");
          newAttribute = null;
       }
       return newAttribute;
  }

	/** Remove the attribute with the specified name from this AttributeManager.
	 */
  public void removeAttribute( String attributeName )
  {
       definedAttributes.remove( attributeName );
  }

	/** Returns true if there is an attribute with the specified name managed
	 * by this attribute manager.
	 */
  public boolean hasAttributeNamed( String attributeName )
  {
      return definedAttributes.containsKey( attributeName );
  }

  /** Returns the attribute with the specified name. Returns null
   * if there is no attribute with that name.
   */
  public Attribute<T> getAttribute( String attributeName )
  {
      return definedAttributes.get(attributeName);
  }

	/** Returns an array of all names of attributes managed by
	 * this AttributeManager.
	 */
  public String[] getAttributeNames()
  {
      String[] names = new String[0];
      names = definedAttributes.keySet().toArray(names);
      return names;
  }
  
  /** Clears all of the attributes managed by this AttributeManager 
   * while leaving the attributes defined.
   */
  @SuppressWarnings("unchecked")
public void clear()
  {
  	Enumeration<?> enu = definedAttributes.elements();
  	while( enu.hasMoreElements() )
  	{
  		Attribute<T> attr = (Attribute<T>) enu.nextElement();
  		attr.clear();
  	}
  }

}
