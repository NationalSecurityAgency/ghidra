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

public interface ByteTrieNodeIfc<T> {

	/**
	 * Returns whether this node represents a byte sequence in the trie
	 * or just an internal node on our way down to one.
	 * @return whether this node represents a terminal value
	 */
	public abstract boolean isTerminal();

	/**
	 * Returns the user item stored in a terminal node (or null in an
	 * internal node).
	 * @return the user item
	 */
	public abstract T getItem();

	/**
	 * Returns a new byte array with the value of the byte sequence represented
	 * by this node (slow, built from scratch every time).
	 * @return the byte sequence
	 */
	public abstract byte[] getValue();

	/**
	 * Returns the length of the byte sequence represented by this node
	 * (cached integer, very fast).
	 * @return the length of the byte sequence
	 */
	public abstract int length();

}
