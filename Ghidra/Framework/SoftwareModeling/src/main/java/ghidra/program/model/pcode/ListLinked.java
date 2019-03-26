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
package ghidra.program.model.pcode;

import java.util.Iterator;
/**
 * 
 *
 * A better linked list implementation than provided by java.util.
 * 
 * TODO: Looks like the main benefit is a non-failing iterator.  In JDK 1.5
 * this may not be needed.  1.5 has better Iterators in the collections classes.
 */
public class ListLinked<T> {

	private class LinkedNode {
		public LinkedNode previousNode;
		public LinkedNode nextNode;
		public T data;
		
		LinkedNode(LinkedNode prev,LinkedNode nxt,T d) {
			previousNode = prev;
			nextNode = nxt;
			data = d;
		}
	}

	private class LinkedIterator implements Iterator<T> {	
		private LinkedNode curNode;			// Current node in the linked list being pointed at by this iterator

		public LinkedIterator(LinkedNode cur) {
			curNode = cur;	
		}
		
		/* (non-Javadoc)
	 	* @see java.util.Iterator#remove()
	 	*/
		public void remove() {
			if (curNode.data == null) return;		// Should probably throw an exception here
			curNode.nextNode.previousNode = curNode.previousNode;
			curNode.previousNode.nextNode = curNode.nextNode;
			curNode = curNode.previousNode;			
		}

		/* (non-Javadoc)
	 	* @see java.util.Iterator#hasNext()
	 	*/
		public boolean hasNext() {
			return (curNode.nextNode.data != null);
		}

		/* (non-Javadoc)
	 	* @see java.util.Iterator#next()
	 	*/
		public T next() {
			curNode = curNode.nextNode;
			return curNode.data;
		}
		
		public boolean hasPrevious() {
			return (curNode.data != null);
		}
		
		public Object previous() {
			curNode = curNode.previousNode;
			return curNode.nextNode.data;
		}
	}
	
	private LinkedNode terminal;				// The boundary of the linked list
	
	ListLinked() {
		terminal = new LinkedNode(null,null,null);
		terminal.nextNode = terminal;
		terminal.previousNode = terminal;				// Create empty list
	}
	
	/**
	 * Add object to end of the list, any existing iterators remain valid
	 * 
	 * @param o -- Object to be added
	 * @return Iterator to new object
	 */
	public Iterator<T> add(T o) {
		LinkedNode newNode = new LinkedNode(terminal.previousNode,terminal,o);
		terminal.previousNode.nextNode = newNode;
		terminal.previousNode = newNode;
		LinkedIterator iter = new LinkedIterator(newNode);
		return iter;	
	}

	/**
	 * Insert new object AFTER object pointed to by iterator, other Iterators remain valid
	 * 
	 * @param itr   Iterator to existing object
	 * @param o    New object to add
	 * @return		Iterator to new object
	 */
	public Iterator<T> insertAfter(Iterator<T> itr,T o) {		// Insert object AFTER object indicated by iter
		LinkedNode cur = ((LinkedIterator) itr).curNode;
		LinkedNode newNode = new LinkedNode(cur,cur.nextNode,o);
		cur.nextNode.previousNode = newNode;
		cur.nextNode = newNode;
		return new LinkedIterator(newNode);
	}
	
	/**
	 * Insert new object BEFORE object pointed to by iterator, other Iterators remain valid
	 * 
	 * @param itr  Iterator to existing object
	 * @param o   New object to add
	 * @return      Iterator to new object
	 */
	public Iterator<T> insertBefore(Iterator<T> itr,T o) {	// Insert BEFORE iterator
		LinkedNode cur = ((LinkedIterator)itr).curNode;
		LinkedNode newNode = new LinkedNode(cur.previousNode,cur,o);
		cur.previousNode.nextNode = newNode;
		cur.previousNode = newNode;
		return new LinkedIterator(newNode);
	}
	
	/**
	 * Remove object from list indicated by Iterator, all iterators that point to objects other
	 * than this one remain valid
	 * 
	 * @param itr   Iterator to object to be removed
	 */
	public void remove(Iterator<T> itr) {
		LinkedNode cur = ((LinkedIterator)itr).curNode;
		if (cur.data == null) return;		// Should probably throw an exception here
		cur.previousNode.nextNode = cur.nextNode;
		cur.nextNode.previousNode = cur.previousNode;
	}

	/**
	 * @return an iterator over this linked list
	 */
	public Iterator<T> iterator() {
		LinkedIterator iter = new LinkedIterator(terminal);			// Build starting iterator
		return iter;	
	}
	
	/**
	 * Get rid of all entries on the linked list.
	 */
	public void clear() {
		terminal.nextNode = terminal;
		terminal.previousNode = terminal;			// Recreate empty list
	}
	
}
