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

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.List;

public interface ByteTrieIfc<T> {

	/**
	 * Returns if the trie is empty.
	 * @return if the trie is empty
	 */
	public abstract boolean isEmpty();

	/**
	 * Returns the number of byte sequences in the trie.
	 * @return the number of byte sequences in the trie
	 */
	public abstract int size();

	/**
	 * Returns the number of nodes in the trie; this is essentially equal
	 * to the sum of the number of characters in all byte sequences present in
	 * the trie, minus their shared prefixes.
	 * @return the number of nodes in the trie
	 */
	public abstract int numberOfNodes();

	/**
	 * Adds a byte sequence to the trie, with corresponding user item.  Returns
	 * if the add took place, or if this add was essentially a replacement of
	 * a previously present value (previous user item is lost forever).
	 * @param value the byte sequence to insert into the trie
	 * @param item a user item to store in that location
	 * @return whether the add took place
	 */
	public abstract boolean add(byte[] value, T item);

	/**
	 * Finds a byte sequence in the trie and returns a node interface object for it,
	 * or null if not present.
	 * @param value the byte sequence sought
	 * @return the node interface if present, or null
	 */
	public abstract ByteTrieNodeIfc<T> find(byte[] value);

	/**
	 * Visits all the nodes in the trie such that the visitation order is properly
	 * byte value ordered. The client is responsible for not performing actions on
	 * non-terminal nodes as necessary.
	 * @param monitor a task monitor
	 * @param op the operation to perform
	 * @throws CancelledException if the user cancels
	 */
	public abstract void inorder(TaskMonitor monitor, Op<T> op) throws CancelledException;

	/**
	 * Search an array of bytes using the Aho-Corasick multiple string
	 * trie search algorithm.
	 * @param text the bytes to search
	 * @return a list of results (tuple of offset position, text found)
	 * @throws CancelledException if the search is cancelled
	 */
	public abstract List<SearchResult<Integer, T>> search(byte[] text, TaskMonitor monitor)
			throws CancelledException;

	/**
	 * Search an array of bytes using the Aho-Corasick multiple string
	 * trie search algorithm.
	 * @param memory the memory to search in
	 * @param view the AddressSetView to restrict the memory search to.
	 * @param monitor the task monitor
	 * @return a list of results (tuple of offset position, text found)
	 * @throws MemoryAccessException if an error occurs reading the memory
	 * @throws CancelledException if the search is cancelled
	 */
	public abstract List<SearchResult<Address, T>> search(Memory memory, AddressSetView view,
			TaskMonitor monitor) throws MemoryAccessException, CancelledException;
}
