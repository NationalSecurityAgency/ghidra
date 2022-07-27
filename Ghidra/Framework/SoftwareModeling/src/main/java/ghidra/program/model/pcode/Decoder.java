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
package ghidra.program.model.pcode;

import java.io.InputStream;

import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;

/**
 * An interface for reading structured data from a stream
 *
 * All data is loosely structured as with an XML document.  A document contains a nested set
 * of elements, with labels corresponding to the ElementId class. A single element can hold
 * zero or more attributes and zero or more child elements.  An attribute holds a primitive
 * data element (boolean, long, String) and is labeled by an AttributeId. The document is traversed
 * using a sequence of openElement() and closeElement() calls, intermixed with read*() calls to extract
 * the data. The elements are traversed in a depth first order.  Attributes within an element can
 * be traversed in order using repeated calls to the getNextAttributeId() method, followed by a calls to
 * one of the read*(void) methods to extract the data.  Alternately a read*(AttributeId) call can be used
 * to extract data for an attribute known to be in the element.  There is a special content attribute
 * whose data can be extracted using a read*(AttributeId) call that is passed the special ATTRIB_CONTENT id.
 * This attribute will not be traversed by getNextAttributeId().
 */
public interface Decoder {

	public AddressFactory getAddressFactory();

	/**
	 * Clear any current decoding state.
	 * Allows the same decoder to be reused. Object is ready for new call to ingestStream.
	 */
	public void clear();

	/**
	 * Prepare to decode a given stream.
	 * Called once before any decoding.  Currently this is assumed to make an internal copy of
	 * the stream data, i.e. the input stream is cleared before any decoding takes place.
	 * @param stream is the given input stream to be decode
	 * @param source is a label describing the source of the input stream
	 * @throws PcodeXMLException for errors reading the stream
	 */
	public void ingestStream(InputStream stream, String source) throws PcodeXMLException;

	/**
	 * Peek at the next child element of the current parent, without traversing in (opening) it.
	 * The element id is returned, which can be compared to ElementId labels.
	 * If there are no remaining child elements to traverse, 0 is returned.
	 * @return the element id or 0
	 */
	public int peekElement();

	/**
	 * Open (traverse into) the next child element of the current parent.
	 * The child becomes the current parent.
	 * The list of attributes is initialized for use with getNextAttributeId.
	 * @return the id of the child element or 0 if there are no additional children
	 */
	public int openElement();

	/**
	 * Open (traverse into) the next child element, which must be of a specific type
	 * The child becomes the current parent, and its attributes are initialized for use with
	 * getNextAttributeId. The child must match the given element id or an exception is thrown.
	 * @param elemId is the given element id to match
	 * @return the id of the child element
	 * @throws PcodeXMLException if the expected element is not the next element
	 */
	public int openElement(ElementId elemId) throws PcodeXMLException;

	/**
	 * Close the current element
	 * The data for the current element is considered fully processed. If the element has additional
	 * children, an exception is thrown. The stream must indicate the end of the element in some way.
	 * @param id is the id of the element to close (which must be the current element)
	 * @throws PcodeXMLException if not at end of expected element
	 */
	public void closeElement(int id) throws PcodeXMLException;

	/**
	 * Close the current element, skipping any child elements that have not yet been parsed.
	 * This closes the given element, which must be current.  If there are child elements that have
	 * not been parsed, this is not considered an error, and they are skipped over in the parse.
	 * @param id is the id of the element to close (which must be the current element)
	 * @throws PcodeXMLException if the indicated element is not the current element
	 */
	public void closeElementSkipping(int id) throws PcodeXMLException;

	/**
	 * Get the next attribute id for the current element
	 * Attributes are automatically set up for traversal using this method, when the element is
	 * opened. If all attributes have been traversed (or there are no attributes), 0 is returned.
	 * @return the id of the next attribute or 0
	 */
	public int getNextAttributeId();

	/**
	 * Reset attribute traversal for the current element
	 * Attributes for a single element can be traversed more than once using the getNextAttributeId
	 * method.
	 */
	public void rewindAttributes();

	/**
	 * Parse the current attribute as a boolean value
	 * The last attribute, as returned by getNextAttributeId, is treated as a boolean, and its
	 * value is returned.
	 * @return the boolean value associated with the current attribute.
	 * @throws PcodeXMLException if the expected value is not present
	 */
	public boolean readBool() throws PcodeXMLException;

	/**
	 * Find and parse a specific attribute in the current element as a boolean value
	 * The set of attributes for the current element is searched for a match to the given attribute
	 * id. This attribute is then parsed as a boolean and its value returned.
	 * If there is no attribute matching the id, an exception is thrown.
	 * Parsing via getNextAttributeId is reset.
	 * @param attribId is the specific attribute id to match
	 * @return the boolean value
	 * @throws PcodeXMLException if the expected value is not present
	 */
	public boolean readBool(AttributeId attribId) throws PcodeXMLException;

	/**
	 * Parse the current attribute as a signed integer value
	 * The last attribute, as returned by getNextAttributeId, is treated as a signed integer,
	 * and its value is returned.
	 * @return the signed integer value associated with the current attribute.
	 * @throws PcodeXMLException if the expected value is not present
	 */
	public long readSignedInteger() throws PcodeXMLException;

	/**
	 * Find and parse a specific attribute in the current element as a signed integer
	 * The set of attributes for the current element is searched for a match to the given attribute
	 * id. This attribute is then parsed as a signed integer and its value returned.
	 * If there is no attribute matching the id, an exception is thrown.
	 * Parsing via getNextAttributeId is reset.
	 * @param attribId is the specific attribute id to match
	 * @return the signed integer value
	 * @throws PcodeXMLException if the expected value is not present
	 */
	public long readSignedInteger(AttributeId attribId) throws PcodeXMLException;

	/**
	 * Parse the current attribute as an unsigned integer value
	 * The last attribute, as returned by getNextAttributeId, is treated as an unsigned integer,
	 * and its value is returned.
	 * @return the unsigned integer value associated with the current attribute.
	 * @throws PcodeXMLException if the expected value is not present
	 */
	public long readUnsignedInteger() throws PcodeXMLException;

	/**
	 * Find and parse a specific attribute in the current element as an unsigned integer
	 * The set of attributes for the current element is searched for a match to the given attribute
	 * id. This attribute is then parsed as an unsigned integer and its value returned.
	 * If there is no attribute matching the id, an exception is thrown.
	 * Parsing via getNextAttributeId is reset.
	 * @param attribId is the specific attribute id to match
	 * @return the unsigned integer value
	 * @throws PcodeXMLException if the expected value is not present
	 */
	public long readUnsignedInteger(AttributeId attribId) throws PcodeXMLException;

	/**
	 * Parse the current attribute as a string
	 * The last attribute, as returned by getNextAttributeId, is returned as a string.
	 * @return the string associated with the current attribute.
	 * @throws PcodeXMLException if the expected value is not present
	 */
	public String readString() throws PcodeXMLException;

	/**
	 * Find the specific attribute in the current element and return it as a string
	 * The set of attributes for the current element is searched for a match to the given attribute
	 * id. This attribute is then returned as a string.  If there is no attribute matching the id,
	 * and exception is thrown. Parse via getNextAttributeId is reset.
	 * @param attribId is the specific attribute id to match
	 * @return the string associated with the attribute
	 * @throws PcodeXMLException if the expected value is not present
	 */
	public String readString(AttributeId attribId) throws PcodeXMLException;

	/**
	 * Parse the current attribute as an address space
	 * The last attribute, as returned by getNextAttributeId, is returned as an address space.
	 * @return the address space associated with the current attribute.
	 * @throws PcodeXMLException if the expected value is not present
	 */
	public AddressSpace readSpace() throws PcodeXMLException;

	/**
	 * Find the specific attribute in the current element and return it as an address space
	 * Search attributes from the current element for a match to the given attribute id.
	 * Return this attribute as an address space. If there is no attribute matching the id, an
	 * exception is thrown. Parse via getNextAttributeId is reset.
	 * @param attribId is the specific attribute id to match
	 * @return the address space associated with the attribute
	 * @throws PcodeXMLException if the expected value is not present
	 */
	public AddressSpace readSpace(AttributeId attribId) throws PcodeXMLException;

	/**
	 * Skip parsing of the next element
	 * The element skipped is the one that would be opened by the next call to openElement.
	 * @throws PcodeXMLException if there is no new element
	 */
	public default void skipElement() throws PcodeXMLException {
		int elemId = openElement();
		closeElementSkipping(elemId);
	}
}
