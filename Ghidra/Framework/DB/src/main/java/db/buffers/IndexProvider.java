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
package db.buffers;

import java.util.Stack;


/**
 * <code>IndexProvider</code> maintains the free index list associated
 * with a BufferFile.  This provider will exhaust the free index list
 * before allocating new indexes.  This provider relies on the BufferFile
 * growing automatically when buffers having indexes beyond the end-of-file 
 * are written.
 */
class IndexProvider {

	private int nextIndex = 0;
	private Stack<Integer> freeIndexStack = new Stack<Integer>();

	/**
	 * Constructor for empty BufferFile.
	 */
	IndexProvider() {
	}
	
	/**
	 * Constructor with initial state.
	 * @param indexCount previously allocated buffer count.
	 * @param freeIndexes list of free buffer indexes.
	 */
	IndexProvider(int indexCount, int[] freeIndexes) {
		nextIndex = indexCount;
		for (int i = 0; i < freeIndexes.length; i++) {
			freeIndexStack.push(new Integer(freeIndexes[i]));
		}
	}
	
	/**
	 * Return the total number of buffer indexes which have been allocated.
	 */
	int getIndexCount() {
		return nextIndex;
	}
	
	/**
	 * Returns the number of free indexes within the
	 * allocated index space.
	 */
	int getFreeIndexCount() {
		return freeIndexStack.size();
	}

	/**
	 * Allocate a new buffer index.  Exhaust free list before
	 * increasing total index count.
	 * @return assigned index
	 */
	int allocateIndex() {
		if (freeIndexStack.isEmpty()) {
			return nextIndex++;
		}
		return freeIndexStack.pop().intValue();
	}
	
	/**
	 * Allocate a specific index.  Current index count will be adjusted if
	 * specified index exceeds current index count;
	 * @param index requested index
	 * @return true if index was successfully allocated
	 */
	boolean allocateIndex(int index) {

		// Increase index count
		if (index >= nextIndex) {
			for (int i = nextIndex; i < index; i++) {
				freeIndexStack.push(new Integer(i));
			}
			nextIndex = index + 1;
			return true;
		}
		
		return freeIndexStack.remove(new Integer(index));
	}
	
	boolean isFree(int index) {
		return freeIndexStack.contains(new Integer(index));
	}
	
	/**
	 * Free the specified buffer
	 * @param index buffer index
	 */
	void freeIndex(int index) {
		freeIndexStack.push(new Integer(index));
	}
	
	/**
	 * Truncate this buffer file.  This method has no affect if the specified 
	 * newBufferCnt is greater than the current buffer count.
	 * @param newIndexCnt new index count
	 * @return true if successful, false if newIndexCnt is larger than current 
	 * index count.
	 */
	boolean truncate(int newIndexCnt) {
		if (newIndexCnt >= nextIndex) {
			return false;
		}
		nextIndex = newIndexCnt;
		
		// Remove free indexes which have been lost
		int cnt = freeIndexStack.size();
		for (int i = cnt-1; i >= 0; --i) {
			int freeIndex = freeIndexStack.get(i).intValue();
			if (freeIndex >= newIndexCnt) {
				freeIndexStack.remove(i);
			}
		}
		return true;
	}
	
	/**
	 * Returns the current list of free indexes for this index provider.
	 * @return free index list
	 */
	int[] getFreeIndexes() {
		int[] freeIndexes = new int[freeIndexStack.size()];
		for (int i = 0; i < freeIndexes.length; i++) {
			freeIndexes[i] = freeIndexStack.get(i).intValue();
		}
		return freeIndexes;
	}

}
