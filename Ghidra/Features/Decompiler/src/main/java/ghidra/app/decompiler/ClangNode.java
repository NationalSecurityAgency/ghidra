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
package ghidra.app.decompiler;

import java.awt.Color;
import java.util.List;

import ghidra.program.model.address.Address;

/**
 * A collection of source code text elements, with associated attributes, grouped in
 * a tree structure.
 */
public interface ClangNode {

	/**
	 * Get the immediate grouping (parent) containing this text element. If this is a
	 * complete document, null is returned.
	 * @return the parent grouping or null
	 */
	public ClangNode Parent();

	/**
	 * Get the smallest Program address associated with the code that this text represents 
	 * @return the smallest Address
	 */
	public Address getMinAddress();

	/**
	 * Get the biggest Program address associated with the code that this text represents
	 * @return the biggest Address
	 */
	public Address getMaxAddress();

	/**
	 * Set a highlighting background color for all text elements
	 * @param c is the color to set
	 */
	public void setHighlight(Color c);

	/**
	 * Return the number of immediate groupings this text breaks up into
	 * @return the number of child groupings
	 */
	public int numChildren();

	/**
	 * Get the i-th child grouping
	 * @param i is the index selecting the grouping
	 * @return the selected grouping
	 */
	public ClangNode Child(int i);

	/**
	 * Get the text representing an entire function of which this is part.
	 * @return text for the whole function
	 */
	public ClangFunction getClangFunction();

	/**
	 * Flatten this text into a list of tokens (see ClangToken)
	 * @param list is the container that will contain the tokens
	 */
	public void flatten(List<ClangNode> list);

}
