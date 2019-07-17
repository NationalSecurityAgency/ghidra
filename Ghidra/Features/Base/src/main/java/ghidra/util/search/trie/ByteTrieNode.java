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
 * Class to represent a (possibly non-terminal!) node within the ByteTrie.
 *
 * @param <T> the user item type
 */
public class ByteTrieNode<T> implements ByteTrieNodeIfc<T> {
	// note we pull this space trick with the byte id and whether we're terminal
	private final static int TERMINAL_MASK = 0x100;
	private final static int ID_MASK = 0xff;

	ByteTrieNode<T>[] children;
	private short idAndTerminality;
	private final int length;
	private final ByteTrieNode<T> parent;

	ByteTrieNode<T> suffix;
	private T item;

	protected byte transformByte(byte v) {
		return v;
	}

	/**
	 * Returns whether this node represents a byte sequence in the trie
	 * or just an internal node on our way down to one.
	 * @return whether this node represents a terminal value
	 */
	@Override
	public boolean isTerminal() {
		return (idAndTerminality & TERMINAL_MASK) != 0;
	}

	/**
	 * Returns the user item stored in a terminal node (or null in an
	 * internal node).
	 * @return the user item
	 */
	@Override
	public T getItem() {
		return item;
	}

	/**
	 * Returns the length of the byte sequence represented by this node
	 * (cached integer, very fast).
	 * @return the length of the byte sequence
	 */
	@Override
	public int length() {
		return length;
	}

	/**
	 * Returns a new byte array with the value of the byte sequence represented
	 * by this node (slow, built from scratch every time).
	 * @return the byte sequence
	 */
	@Override
	public byte[] getValue() {
		int count = 0;
		ByteTrieNode<T> node = this;
		while (node.parent != null) {
			++count;
			node = node.parent;
		}
		byte[] result = new byte[count];
		int index = count - 1;
		node = this;
		while (node.parent != null) {
			result[index--] = node.getId();
			node = node.parent;
		}
		return result;
	}

	/**
	 * Returns the final byte in the byte sequence represented by this node
	 * (fast, but uses a bitmask).
	 * @return the final byte in the byte sequence
	 */
	protected byte getId() {
		return (byte) (idAndTerminality & ID_MASK);
	}

	/**
	 * Returns the child node (successor in the byte sequence) which
	 * has byte value, or null if no such child exists.
	 * @param value the byte value
	 * @return the child node if present or null
	 */
	public ByteTrieNode<T> getChild(byte value) {
		value = transformByte(value);
		if (children.length == 0) {
			return null;
		}
		else if (children.length == 1) {
			if (transformByte(children[0].getId()) == value) {
				return children[0];
			}
			return null;
		}
		else if (children.length == 2) {
			if (transformByte(children[0].getId()) == value) {
				return children[0];
			}
			if (transformByte(children[1].getId()) == value) {
				return children[1];
			}
			return null;
		}
		int index = findIndex(value);
		if (index >= children.length) {
			return null;
		}
		ByteTrieNode<T> child = children[index];
		if (transformByte(child.getId()) == value) {
			return child;
		}
		return null;
	}

	/**
	 * Adds a child to children.  Note that we're using two quick static
	 * size cases (0 and 1) to speed things up early on, and then binary
	 * search on the children array to find the index.  We then allocate
	 * a new array and insert the new node at the appropriate index, so
	 * this operation is big-O of lg n.
	 * @param value the byte value
	 * @param child the child node
	 */
	void addChild(byte value, ByteTrieNode<T> child) {
		value = transformByte(value);
		@SuppressWarnings("unchecked")
		ByteTrieNode<T>[] newChildren = new ByteTrieNode[children.length + 1];
		if (children.length == 0) {
			newChildren[0] = child;
			children = newChildren;
			return;
		}
		if (children.length == 1) {
			if (value < transformByte(children[0].getId())) {
				newChildren[0] = child;
				newChildren[1] = children[0];
			}
			else {
				newChildren[0] = children[0];
				newChildren[1] = child;
			}
			children = newChildren;
			return;
		}
		int newChildIndex = findIndex(value);
		for (int ii = 0; ii < newChildIndex; ++ii) {
			newChildren[ii] = children[ii];
		}
		newChildren[newChildIndex] = child;
		for (int ii = newChildIndex + 1; ii < newChildren.length; ++ii) {
			newChildren[ii] = children[ii - 1];
		}
		children = newChildren;
	}

	/**
	 * Use binary search to find the index where the value is
	 * (or should be, in case of add).
	 * @param value the byte value
	 * @return the index (from 0 to length of children, inclusive)
	 */
	private int findIndex(byte value) {
		if (children.length == 0) {
			return 0;
		}

		int left = 0;
		int right = children.length;

		while (right >= left) {
			int mid = (left + right) / 2;
			if (mid >= children.length) {
				return mid;
			}
			ByteTrieNode<T> child = children[mid];
			byte id = transformByte(child.getId());
			if (id == value) {
				return mid;
			}
			else if (id < value) {
				left = mid + 1;
			}
			else {
				right = mid - 1;
			}
		}
		return left;
	}

	@SuppressWarnings("unchecked")
	ByteTrieNode(byte id, ByteTrieNode<T> parent, int length) {
		this.children = new ByteTrieNode[0];
		// NOTE: isTerminal "flag" is 0, as in NOT terminal
		this.idAndTerminality = (short) (id & ID_MASK);
		this.parent = parent;
		this.length = length;
	}

	/**
	 * Sets this node to be terminal, and the user item.
	 * @param item the user item to store in the node
	 */
	void setTerminal(T item) {
		this.idAndTerminality |= TERMINAL_MASK;
		this.item = item;
	}

	// only useful during debugging; note that it is recursive and make big string!
	@Override
	public String toString() {
		if (parent == null) {
			return (isTerminal() ? "*" : "") + "-";
		}
		return String.format((isTerminal() ? "*" : "") + "%s:%c  s:[%s]",
			debugByteArray(getValue()), getId(), suffix);
	}

	private static String debugByteArray(byte[] array) {
		StringBuilder sb = new StringBuilder();
		for (byte b : array) {
			if (b > 31 && b < 127) {
				sb.append((char) b);
			}
			else {
				sb.append(String.format("\\x%02x", (byte) (b & 0xff)));
			}
		}
		return sb.toString();
	}
}
