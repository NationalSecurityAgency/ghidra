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

import java.io.IOException;
import java.io.OutputStream;

import ghidra.program.model.address.AddressSpace;

/**
 * An interface for writing structured data to a stream
 *
 * The resulting encoded data is structured similarly to an XML document. The document contains a nested set
 * of \elements, with labels corresponding to the ElementId class. A single element can hold
 * zero or more attributes and zero or more child elements.  An attribute holds a primitive
 * data element (boolean, long, String) and is labeled by an AttributeId. The document is written
 * using a sequence of openElement() and closeElement() calls, intermixed with write*() calls to encode
 * the data primitives.  All primitives written using a write*() call are associated with current open element,
 * and all write*() calls for one element must come before opening any child element.
 * The traditional XML element text content can be written using the special ATTRIB_CONTENT AttributeId, which
 * must be the last write*() call associated with the specific element.
 */
public interface Encoder {

	/**
	 * Clear any state associated with the encoder
	 * The encoder should be ready to write a new document after this call.
	 */
	void clear();

	/**
	 * Begin a new element in the encoding
	 * The element will have the given ElementId annotation and becomes the \e current element.
	 * @param elemId is the given ElementId annotation
	 * @throws IOException for errors in the underlying stream
	 */
	void openElement(ElementId elemId) throws IOException;

	/**
	 * End the current element in the encoding
	 * The current element must match the given annotation or an exception is thrown.
	 * @param elemId is the given (expected) annotation for the current element
	 * @throws IOException for errors in the underlying stream
	 */
	void closeElement(ElementId elemId) throws IOException;

	/**
	 * Write an annotated boolean value into the encoding
	 * The boolean data is associated with the given AttributeId annotation and the current open element.
	 * @param attribId is the given AttributeId annotation
	 * @param val is boolean value to encode
	 * @throws IOException for errors in the underlying stream
	 */
	void writeBool(AttributeId attribId, boolean val) throws IOException;

	/**
	 * Write an annotated signed integer value into the encoding
	 * The integer is associated with the given AttributeId annotation and the current open element.
	 * @param attribId is the given AttributeId annotation
	 * @param val is the signed integer value to encode
	 * @throws IOException for errors in the underlying stream
	 */
	void writeSignedInteger(AttributeId attribId, long val) throws IOException;

	/**
	 * Write an annotated unsigned integer value into the encoding
	 * The integer is associated with the given AttributeId annotation and the current open element.
	 * @param attribId is the given AttributeId annotation
	 * @param val is the unsigned integer value to encode
	 * @throws IOException for errors in the underlying stream
	 */
	void writeUnsignedInteger(AttributeId attribId, long val) throws IOException;

	/**
	 * Write an annotated string into the encoding
	 * The string is associated with the given AttributeId annotation and the current open element.
	 * @param attribId is the given AttributeId annotation
	 * @param val is the string to encode
	 * @throws IOException for errors in the underlying stream
	 */
	void writeString(AttributeId attribId, String val) throws IOException;

	/**
	 * Write an annotated string, using an indexed attribute, into the encoding.
	 * Multiple attributes with a shared name can be written to the same element by calling this
	 * method multiple times with a different index value. The encoding will use attribute ids up
	 * to the base id plus the maximum index passed in.  Implementors must be careful to not use
	 * other attributes with ids bigger than the base id within the element taking the indexed attribute.
	 * @param attribId is the shared AttributeId
	 * @param index is the unique index to associated with the string
	 * @param val is the string to encode
	 * @throws IOException for errors in the underlying stream
	 */
	void writeStringIndexed(AttributeId attribId, int index, String val) throws IOException;

	/**
	 * Write an address space reference into the encoding
	 * The address space is associated with the given AttributeId annotation and the current open element.
	 * @param attribId is the given AttributeId annotation
	 * @param spc is the address space to encode
	 * @throws IOException for errors in the underlying stream
	 */
	void writeSpace(AttributeId attribId, AddressSpace spc) throws IOException;

	/**
	 * Dump all the accumulated bytes in this encoder to the stream.
	 * @param stream is the output stream
	 * @throws IOException for errors during the write operation
	 */
	public void writeTo(OutputStream stream) throws IOException;

	/**
	 * The encoder is considered empty if the writeTo() method would output zero bytes
	 * @return true if there are no bytes in the encoder
	 */
	public boolean isEmpty();
}
