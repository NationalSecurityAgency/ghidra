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

import ghidra.program.model.address.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.math.BigInteger;
import java.util.*;

/**
 * ByteTrie is a byte-based trie specifically designed to implement the Aho-Corasick
 * string search algorithm.
 *
 * @param <T> the item storage type
 */
public class ByteTrie<T> implements ByteTrieIfc<T> {
	// 1M buffer size when searching memory
	private static final int BUFFER_SIZE = 1 << 20;

	private static long GVID = Long.MIN_VALUE;

	/**
	 * Returns a version id for the trie to lazily schedule
	 * suffix (failure) pointers.
	 * @return an auto-incrementing version id
	 */
	private synchronized static long getVersionId() {
		return ++GVID;
	}

	private ByteTrieNode<T> root;
	private long versionId;
	private long suffixId;
	private int size;
	private int numberOfNodes;

	protected ByteTrieNode<T> generateNode(byte id, ByteTrieNode<T> parent, int length) {
		return new ByteTrieNode<T>(id, parent, length);
	}

	public ByteTrie() {
		root = generateNode((byte) 0, null, 0);
		versionId = getVersionId();
		suffixId = Long.MIN_VALUE;
		size = 0;
		numberOfNodes = 1;
	}

	/**
	 * Returns if the trie is empty.
	 * @return if the trie is empty
	 */
	@Override
	public boolean isEmpty() {
		return size() == 0;
	}

	/**
	 * Returns the number of byte sequences in the trie.
	 * @return the number of byte sequences in the trie
	 */
	@Override
	public int size() {
		return size;
	}

	/**
	 * Returns the number of nodes in the trie; this is essentially equal
	 * to the sum of the number of characters in all byte sequences present in
	 * the trie, minus their shared prefixes.
	 * @return the number of nodes in the trie
	 */
	@Override
	public int numberOfNodes() {
		return numberOfNodes;
	}

	/**
	 * Adds a byte sequence to the trie, with corresponding user item.  Returns
	 * if the add took place, or if this add was essentially a replacement of
	 * a previously present value (previous user item is lost forever).
	 * @param value the byte sequence to insert into the trie
	 * @param item a user item to store in that location
	 * @return whether the add took place
	 */
	@Override
	public boolean add(byte[] value, T item) {
		boolean absent;
		versionId = getVersionId();
		if (value == null) {
			absent = !root.isTerminal();
			root.setTerminal(null);
			if (absent) {
				++size;
			}
			return absent;
		}
		ByteTrieNode<T> node = root;
		int offset = 0;
		while (offset < value.length) {
			byte c = value[offset];
			ByteTrieNode<T> childNode = node.getChild(c);
			if (childNode == null) {
				childNode = generateNode(c, node, node.length() + 1);
				node.addChild(c, childNode);
				++numberOfNodes;
			}
			++offset;
			node = childNode;
		}
		absent = !node.isTerminal();
		node.setTerminal(item);
		if (absent) {
			++size;
		}
		return absent;
	}

	/**
	 * Finds a byte sequence in the trie and returns a node interface object for it,
	 * or null if not present.
	 * @param value the byte sequence sought
	 * @return the node interface if present, or null
	 */
	@Override
	public ByteTrieNodeIfc<T> find(byte[] value) {
		if (value == null) {
			return root;
		}
		int offset = 0;
		ByteTrieNodeIfc<T> node = root;
		while (offset < value.length) {
			byte c = value[offset];
			ByteTrieNodeIfc<T> childNode = ((ByteTrieNode<T>) node).getChild(c);
			if (childNode == null) {
				return null;
			}
			++offset;
			node = childNode;
		}
		return node;
	}

	/**
	 * Visits all the nodes in the trie such that the visitation order is properly
	 * ordered (even though the actual algorithm below is a PREORDER traversal).
	 * The client is responsible for not performing actions on non-terminal nodes
	 * as necessary.
	 * @param monitor a task monitor
	 * @param op the operation to perform
	 * @throws CancelledException if the user cancels
	 */
	@Override
	public void inorder(TaskMonitor monitor, Op<T> op) throws CancelledException {
		Stack<ByteTrieNode<T>> parentStack = new Stack<ByteTrieNode<T>>();
		parentStack.push(null);
		ByteTrieNode<T> top = root;
		monitor.initialize(numberOfNodes());
		while (top != null) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);
			op.op(top);
			if (top.children.length == 0) {
				top = parentStack.pop();
			}
			else {
				for (int ii = top.children.length - 1; ii > 0; --ii) {
					parentStack.push(top.children[ii]);
				}
				top = top.children[0];
			}
		}
	}

	/**
	 * Search an array of bytes using the Aho-Corasick multiple string
	 * trie search algorithm.
	 * @param text the bytes to search
	 * @param monitor a task monitor
	 * @return a list of search results
	 * @throws CancelledException
	 */
	@Override
	public List<SearchResult<Integer, T>> search(byte[] text, TaskMonitor monitor)
			throws CancelledException {
		monitor.initialize(numberOfNodes() + text.length);
		fixupSuffixPointers(monitor);
		ArrayList<SearchResult<Integer, T>> results = new ArrayList<SearchResult<Integer, T>>();
		ByteTrieNode<T> ptr = root;
		int index = 0;
		while (index < text.length) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);
			ByteTrieNode<T> trans = null;
			while (trans == null) {
				trans = getTransition(ptr, text[index]);
				if (ptr == root) {
					break;
				}
				if (trans == null) {
					ptr = ptr.suffix;
				}
			}
			if (trans != null) {
				ptr = trans;
			}
			ByteTrieNode<T> tmp = ptr;
			while (tmp != root) {
				if (tmp.isTerminal()) {
					results.add(new SearchResult<Integer, T>(tmp, index - tmp.length() + 1,
						tmp.getItem()));
				}
				tmp = tmp.suffix;
			}
			++index;
		}
		return results;
	}

	/**
	 * Search memory using the Aho-Corasick multiple string
	 * trie search algorithm.
	 * @param memory the program memory manager
	 * @param view the address set view to search
	 * @param monitor a task monitor
	 * @return a list of search results
	 * @throws MemoryAccessException if bytes are not available
	 * @throws CancelledException if the user cancels
	 */
	@Override
	public List<SearchResult<Address, T>> search(Memory memory, AddressSetView view,
			TaskMonitor monitor) throws MemoryAccessException, CancelledException {
		AddressSetView initView = memory.getLoadedAndInitializedAddressSet().intersect(view);
		monitor.initialize(numberOfNodes() + initView.getNumAddresses());

		fixupSuffixPointers(monitor);
		ArrayList<SearchResult<Address, T>> results = new ArrayList<SearchResult<Address, T>>();
		byte[] buffer = new byte[BUFFER_SIZE];

		AddressRangeIterator addressRanges = initView.getAddressRanges(true);
		while (addressRanges.hasNext()) {
			AddressRange range = addressRanges.next();
			BigInteger rangeLength = range.getBigLength();
			int fetchSize = BUFFER_SIZE;
			if (rangeLength.compareTo(BigInteger.valueOf(BUFFER_SIZE)) < 0) {
				fetchSize = rangeLength.intValue();
			}
			ByteTrieNode<T> ptr = root;
			Address address = range.getMinAddress();
			while (range.contains(address)) {
				monitor.checkCanceled();
				final int bytesRead = memory.getBytes(address, buffer, 0, fetchSize);
				monitor.incrementProgress(bytesRead);

				int index = 0;
				while (index < bytesRead) {
					ByteTrieNode<T> trans = null;
					while (trans == null) {
						trans = getTransition(ptr, buffer[index]);
						if (ptr == root) {
							break;
						}
						if (trans == null) {
							ptr = ptr.suffix;
						}
					}
					if (trans != null) {
						ptr = trans;
					}
					ByteTrieNode<T> tmp = ptr;
					while (tmp != root) {
						if (tmp.isTerminal()) {
							int offset = index - tmp.length() + 1;
							Address position = address.add(offset);
							results.add(new SearchResult<Address, T>(tmp, position, tmp.getItem()));
						}
						tmp = tmp.suffix;
					}
					++index;
				}

				try {
					address = address.add(bytesRead);
				}
				catch (AddressOutOfBoundsException e) {
					break; // hit end of address space
				}
			}
		}

		return results;
	}

	/**
	 * BFS fixup of suffix (failure) pointers, but only if we need to (the 
	 * version id is more advanced than our last suffix fixup id).
	 * @param monitor a task monitor
	 * @throws CancelledException if the user cancels
	 */
	private void fixupSuffixPointers(final TaskMonitor monitor) throws CancelledException {
		if (versionId > suffixId) {
			LinkedList<ByteTrieNode<T>> queue = new LinkedList<ByteTrieNode<T>>();
			for (int ii = 0; ii < root.children.length; ++ii) {
				ByteTrieNode<T> child = root.children[ii];
				child.suffix = root;
				queue.addLast(child);
			}
			root.suffix = root;
			while (!queue.isEmpty()) {
				monitor.checkCanceled();
				monitor.incrementProgress(1);
				ByteTrieNode<T> node = queue.removeFirst();
				for (int ii = 0; ii < node.children.length; ++ii) {
					ByteTrieNode<T> tmp = node;
					byte id = node.children[ii].getId();
					ByteTrieNode<T> tmpChild = tmp.getChild(id);
					queue.addLast(tmpChild);
					tmp = tmp.suffix;
					while (tmp != root && tmp.getChild(id) == null) {
						tmp = tmp.suffix;
					}
					tmpChild.suffix = tmp.getChild(id);
					if (tmpChild.suffix == null) {
						tmpChild.suffix = root;
					}
				}
			}

			suffixId = getVersionId();
		}
	}

	/**
	 * Find our transition, either our child, or our suffix's child, etc. etc.
	 * @param ptr the current node pointer
	 * @param value the next byte value
	 * @return the proper transition node
	 */
	private ByteTrieNode<T> getTransition(ByteTrieNode<T> ptr, byte value) {
		ByteTrieNode<T> child = ptr.getChild(value);
		while (child == null && ptr != root) {
			ptr = ptr.suffix;
			child = ptr.getChild(value);
		}
		if (child != null) {
			return child;
		}
		return root;
	}
}
