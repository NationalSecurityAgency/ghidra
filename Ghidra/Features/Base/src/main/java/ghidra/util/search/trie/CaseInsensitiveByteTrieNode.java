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
 * Class to represent a (possibly non-terminal!) node within the CaseInsensitiveByteTrie.
 *
 * @param <T> the user item type
 */
public class CaseInsensitiveByteTrieNode<T> extends ByteTrieNode<T> {
	/*
	 * For the factory method in the derived trie class...
	 */
	CaseInsensitiveByteTrieNode(byte id, ByteTrieNode<T> parent, int length) {
		super(id, parent, length);
	}

	private static final byte OFFSET = 'a' - 'A';

	/*
	 * Pretty simple...the super class (regular trie) handles all the places where
	 * you need to do comparisons by calling this transformation method.  Just
	 * changes uppercase to lowercase, all done.
	 */
	@Override
	protected byte transformByte(byte v) {
		if (v >= 'a' && v <= 'z') {
			v -= OFFSET;
		}
		return v;
	}
}
