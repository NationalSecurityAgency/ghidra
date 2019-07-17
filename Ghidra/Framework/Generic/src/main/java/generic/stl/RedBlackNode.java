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
package generic.stl;

// RedBlack Tree node

public class RedBlackNode<K, V> {
	enum NodeColor{
		RED, BLACK
	}    
	
	K key;
	V value;
    NodeColor color;
    RedBlackNode<K,V> parent;
    RedBlackNode<K,V> left;
    RedBlackNode<K,V> right;
    
    RedBlackNode(K key, V value, RedBlackNode<K,V> parent) {
        this.key = key;
        this.value = value;
        this.parent = parent;
        this.color = NodeColor.BLACK;
    }
    
    @Override
    public String toString() {
        return "" + value;
    }
    
	public V getValue() {
		return value;
	}

	public void setValue(V value) {
		this.value = value;
	}

	public K getKey() {
		return key;
	}


	public RedBlackNode<K, V> getSuccessor() {
		if (right != null) {
			RedBlackNode<K,V> node = right;
			while(node.left != null) {
				node = node.left;
			}
			return node;
		}
		RedBlackNode<K, V> node = this;
		while(node.parent != null) {
			if (node.isLeftChild()) {
				return node.parent;
			}
			node = node.parent;
		}
		return null;
	}
	
	public RedBlackNode<K, V> getPredecessor() {
		if (left != null) {
			RedBlackNode<K,V> node = left;
			while(node.right != null) {
				node = node.right;
			}
			return node;
		}
		RedBlackNode<K, V> node = this;
		while(node.parent != null) {
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

	
}
