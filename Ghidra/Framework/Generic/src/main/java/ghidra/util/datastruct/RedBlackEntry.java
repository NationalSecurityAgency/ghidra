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
package ghidra.util.datastruct;

import java.util.Map;

// RedBlack Tree node

public class RedBlackEntry<K, V> implements Map.Entry<K, V> {
	enum NodeColor {
		RED, BLACK
	}

	final K key;
	V value;
	NodeColor color;
	RedBlackEntry<K, V> parent;
	RedBlackEntry<K, V> left;
	RedBlackEntry<K, V> right;

	RedBlackEntry(K key, V value, RedBlackEntry<K, V> parent) {
		this.key = key;
		this.value = value;
		this.parent = parent;
		this.color = NodeColor.BLACK;
	}

	@Override
	public V getValue() {
		return value;
	}

	@Override
	public V setValue(V value) {
		V oldValue = value;
		this.value = value;
		return oldValue;
	}

	@Override
	public K getKey() {
		return key;
	}

	public RedBlackEntry<K, V> getSuccessor() {
		if (right != null) {
			RedBlackEntry<K, V> node = right;
			while (node.left != null) {
				node = node.left;
			}
			return node;
		}
		RedBlackEntry<K, V> node = this;
		while (node.parent != null) {
			if (node.isLeftChild()) {
				return node.parent;
			}
			node = node.parent;
		}
		return null;
	}

	public RedBlackEntry<K, V> getPredecessor() {
		if (left != null) {
			RedBlackEntry<K, V> node = left;
			while (node.right != null) {
				node = node.right;
			}
			return node;
		}
		RedBlackEntry<K, V> node = this;
		while (node.parent != null) {
			if (!node.isLeftChild()) {
				return node.parent;
			}
			node = node.parent;
		}
		return null;
	}

	boolean isLeftChild() {
		return parent.left == this;
	}

	boolean isRightChild() {
		return parent.right == this;
	}

	public boolean isDisposed() {
		return color == null;
	}

}
