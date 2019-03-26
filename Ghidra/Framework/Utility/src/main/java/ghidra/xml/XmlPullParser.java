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
package ghidra.xml;

/**
 * An interface describing the API for the XML pull parsing system. This is
 * similar to XmlParser, except that it has slightly different methods and IS
 * case sensitive, conforming to the XML spec.
 * 
 * 
 * 
 */
public interface XmlPullParser {
    /**
     * Returns the name of this parser.
     * 
     * @return the name of this parser
     */
    public String getName();

	/**
	 * Returns the value of the attribute of the processing instruction.
	 * For example, <code>&lt;?program_dtd version="1"?&gt;</code>
	 * @param name the name of the processing instruction
	 * @param attribute the name of the attribute
	 * @return the value of the attribute of the processing instruction
	 */
	public String getProcessingInstruction(String name, String attribute);

    /**
     * Returns the current line number where the parser is (note that this may
     * actually be ahead of where you think it is because of look-ahead and
     * caching).
     * 
     * @return the current line number
     */
    public int getLineNumber();

    /**
     * Returns the current column number where the parser is (note that this may
     * actually be ahead of where you think it is because of look-ahead and
     * caching).
     * 
     * @return the current column number
     */
    public int getColumnNumber();

    /**
     * Returns whether the parser will return content elements as well as start
     * and end elements (they're always accumulated and provided in the
     * appropriate end element).
     * 
     * @return whether the parser will return content elements
     */
    public boolean isPullingContent();

    /**
     * Set whether the parser will return content elements. Note that this
     * method may throw an exception if the parser cannot comply with the
     * setting (usually when setting to true).
     * 
     * @param pullingContent
     *            whether the parser will return content elements
     */
    public void setPullingContent(boolean pullingContent);

    /**
     * The current element level, as if the XML document was a tree. The root
     * element is at level 0. Each child is at a level one higher than its
     * parent.
     * 
     * Note that this is the same as peek().getLevel().
     * 
     * @return the current element level
     */
    public int getCurrentLevel();

    /**
     * Returns whether there is a next element.
     * 
     * @return whether there is a next element
     */
    public boolean hasNext();

    /**
     * Returns the next element, without removing it from the queue (assuming
     * there is such a next element). This is very useful for examining the next
     * item to decide who should handle the subtree, and then delegating to a
     * subordinate with the parser state intact.
     * 
     * @return the next element, without removing it
     */
    public XmlElement peek();

    /**
     * Returns the next element, removing it from the queue (assuming there is
     * such a next element). This method should be used RARELY. Typically, when
     * you're reading XML, you almost always at least know that you're either
     * starting or ending a subtree, so start() or end() should be used instead.
     * The only time you really might need to use this is if you don't really
     * know where you are and you need to pop elements off until you synchronize
     * back into a sane state.
     * 
     * @return the next element, removing it
     */
    public XmlElement next();

    /**
     * Returns the next element, which must be a start element, and must be one
     * of the supplied names (if provided). This method is very useful for
     * starting a subtree, and throws an XmlException if the next element does
     * not conform to your specification.
     * 
     * @param names
     *            optional vararg Strings which start element name must be one
     *            of
     * @return the next element (which is a start element)
     */
    public XmlElement start(String... names);

    /**
     * Returns the next element, which must be an end element. The name doesn't
     * matter. This method throws an XmlException if the next element is not an
     * end element. Use this method when you really know you're matching the
     * right end and want to avoid extra constraint checks.
     * 
     * @return the next element (which is an end element)
     */
    public XmlElement end();

    /**
     * Returns the next element, which must be an end element, and must match
     * the supplied XmlElement's name (presumably the start element of the
     * subtree). This method throws an XmlException if the next element is not
     * an end element, or if the name doesn't match.
     * 
     * @param element
     *            the presumed start element to match names
     * @return the next element (which is an end element)
     */
    public XmlElement end(XmlElement element);

    /**
     * Returns the next element, which must be a start element, and must be one
     * of the supplied names (if provided). This method is very useful for
     * starting a subtree, but differs from start(...) in that failures are
     * soft. This means that if the next element isn't a start element, or
     * doesn't match one of the optional provided names, null is returned
     * (instead of raising an XmlException).
     * 
     * @param names
     *            optional vararg Strings which start element name must be one
     *            of
     * @return the next element (which is a start element) or null
     */
    public XmlElement softStart(String... names);

    /**
     * Discards the current subtree. If the current element (peek()) is a
     * content or end element, then just that element is discarded. If it's a
     * start element, then the entire subtree starting with the start element is
     * discarded (i.e. next() is called until the current element is now the
     * element after the subtree's end element).
     * 
     * @return the number of elements discarded
     */
    public int discardSubTree();

    /**
     * Discards the current subtree. The current element must be a start
     * element, and must be named name, otherwise an XmlException is thrown.
     * 
     * @param name
     *            what the current start element must be named
     * @return the number of elements discarded
     */
    public int discardSubTree(String name);

    /**
     * Discards a subtree. The element provided is used as the "start" of the
     * subtree (although it doesn't actually have to be a start element; only
     * its name and level are used). The queue of elements is discarded such
     * that the last element discarded is an end element, has the same name as
     * the provided element, and is the same level as the provided element. If
     * the provided element's level is higher than the current level, then
     * nothing is discarded.
     * 
     * @param element
     *            the element provided as the "start" element
     * @return the number of elements discarded
     */
    public int discardSubTree(XmlElement element);

    /**
     * Disposes all resources of the parser. It's important that this is called
     * when a client is finished with the parser, because this allows files to
     * be closed, threads to be stopped, etc.
     */
    public void dispose();
}
