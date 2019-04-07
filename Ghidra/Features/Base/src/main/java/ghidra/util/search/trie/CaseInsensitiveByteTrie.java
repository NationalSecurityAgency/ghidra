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
 * CaseInsensitiveByteTrie is a byte-based trie specifically designed to implement the Aho-Corasick
 * string search algorithm, matching alphabetic characters ignoring case.
 *
 * @param <T> the item storage type
 */
public class CaseInsensitiveByteTrie<T> extends ByteTrie<T> {
	/*
	 * All we need to do is change the byte trie node factory method in the super class;
	 * everything else is handled in the case insensitive node implementation.
	 */
	@Override
	protected ByteTrieNode<T> generateNode(byte id, ByteTrieNode<T> parent, int length) {
		return new CaseInsensitiveByteTrieNode<T>(id, parent, length);
	}
}
