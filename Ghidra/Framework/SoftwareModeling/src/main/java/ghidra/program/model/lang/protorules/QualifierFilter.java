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
package ghidra.program.model.lang.protorules;

import static ghidra.program.model.pcode.ElementId.*;

import java.io.IOException;

import ghidra.program.model.lang.PrototypePieces;
import ghidra.program.model.pcode.Encoder;
import ghidra.xml.*;

/**
 * A filter on some aspect of a specific function prototype.
 * An instance is configured via the restoreXml() method, then a test of whether
 * a function prototype meets its criteria can be performed by calling its filter() method.
 */
public interface QualifierFilter {
	/**
	 * Make a copy of this qualifier
	 * @return the copy
	 */
	public QualifierFilter clone();

	/**
	 * Test if the given filter is configured and performs identically to this
	 * @param op is the given filter
	 * @return true if the two filters are equivalent
	 */
	public boolean isEquivalent(QualifierFilter op);

	/**
	 * Test whether the given function prototype meets this filter's criteria
	* @param proto is the high-level description of the function prototype to test
	* @param pos is the position of a specific output (pos=-1) or input (pos >=0) in context
	* @return true if the prototype meets the criteria, false otherwise
	*/
	public boolean filter(PrototypePieces proto, int pos);

	/**
	 * Save this filter and its configuration to a stream
	 * @param encoder is the stream encoder
	 * @throws IOException for problems writing to the stream
	 */
	public void encode(Encoder encoder) throws IOException;

	/**
	 * Configure details of the criteria being filtered from the given stream
	* @param parser is the given stream decoder
	 * @throws XmlParseException if there are problems with the stream
	*/
	public void restoreXml(XmlPullParser parser) throws XmlParseException;

	/**
	 * Instantiate a qualifier from the stream. If the next element is not a qualifier,
	 * return null.
	 * @param parser is the given stream decoder
	 * @return the new qualifier instance or null
	 * @throws XmlParseException for problems decoding the stream
	 */
	public static QualifierFilter restoreFilterXml(XmlPullParser parser) throws XmlParseException {
		QualifierFilter filter;
		XmlElement elemId = parser.peek();
		String nm = elemId.getName();
		if (nm.equals(ELEM_VARARGS.name())) {
			filter = new VarargsFilter();
		}
		else if (nm.equals(ELEM_POSITION.name())) {
			filter = new PositionMatchFilter(-1);
		}
		else if (nm.equals(ELEM_DATATYPE_AT.name())) {
			filter = new DatatypeMatchFilter();
		}
		else {
			return null;
		}
		filter.restoreXml(parser);
		return filter;
	}

}
