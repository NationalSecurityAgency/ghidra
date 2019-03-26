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
package ghidra.util.search.trie;

/**
 * A search result container class used with ByteTrie.
 *
 * @param <P> the position type
 * @param <T> the client item type
 */
public class SearchResult<P, T> {
	final ByteTrieNodeIfc<T> node;
	final P position;
	final T item;

	SearchResult(ByteTrieNodeIfc<T> node, P position, T item) {
		this.node = node;
		this.position = position;
		this.item = item;
	}

	/**
	 * Returns the (terminal) node that was encountered in the search
	 * @return the node
	 */
	public ByteTrieNodeIfc<T> getNode() {
		return node;
	}

	/**
	 * Returns the position at which the byte sequence was found.  Currently
	 * ByteTrie will use Integer for search byte arrays, and Address
	 * for searching Memory in a Program.
	 * @return the position at which the byte sequence was found
	 */
	public P getPosition() {
		return position;
	}

	/**
	 * Returns the user item stored in this terminal node at add time.
	 * @return the user item
	 */
	public T getItem() {
		return item;
	}

	@Override
	public String toString() {
		return item + ":" + position;
	}
}
