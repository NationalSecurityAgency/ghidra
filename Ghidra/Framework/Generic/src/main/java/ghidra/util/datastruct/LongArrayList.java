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
package ghidra.util.datastruct;

import ghidra.util.Msg;

import java.util.*;


/**
 * An ArrayList for longs.
 */
public class LongArrayList implements List<Long> {
    public static final int MIN_SIZE = 4;

    private long [] longs;
    private int size = 0;

    /** Creates a new LongArrayList */
    public LongArrayList() {
        longs = new long[MIN_SIZE];
    }

	/**
	 * Creates a new Long ArrayList using the values in the given array
	 * @param arr array of longs to initialize to.
	 */
    public LongArrayList(long [] arr) {
    	longs = arr;
    	size = arr.length;
    }
    
    /**
     * Creates a new LongArrayList that is equivalent to the specified LongArrayList.
     * It creates a copy of the specified list.
     * @param list the list to be copied.
     */
    public LongArrayList(LongArrayList list) {
		size = list.size;
    	longs = new long[Math.max(size, MIN_SIZE)];
    	System.arraycopy(list.longs, 0, longs, 0, size);
    }

	public void add(long value) {
		add(size, value);
	}

	/**
	 * @see java.util.List#add(java.lang.Object)
	 */
	public boolean add(Long value) {
		add(size, value);
		return true;
	}


	/**
	 * @see java.util.List#add(int, java.lang.Object)
	 */
	public void add(int index, Long value) {
		add(index, value.longValue());
	}
	
	public void add(int index, long value) {
    	if (index < 0 || index > size) {
    		throw new IndexOutOfBoundsException();
    	}
        if (size == longs.length) {
            growArray();
        }
		try {
	        System.arraycopy(longs, index, longs, index+1, size-index);
		} catch(Exception e) {
		    Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
	
        longs[index] = value;
		size++;
    }

    public Long remove(int index) {
    	if (index < 0 || index >= size) {
    		throw new IndexOutOfBoundsException();
    	}
    	Long returnValue = longs[index];
        System.arraycopy(longs, index+1, longs, index, size-index-1);
		size--;
		if (size < longs.length / 4) {
			shrinkArray();
		}
		return returnValue;
    }

    /**
     * @see java.util.List#get(int)
     */
    public Long get(int index) {
    	if (index < 0 || index >= size) {
    		throw new IndexOutOfBoundsException();
    	}
        return longs[index];
    }
    public long getLongValue(int index) {
    	if (index < 0 || index >= size) {
    		throw new IndexOutOfBoundsException();
    	}
        return longs[index];
    }
	/**
	 * @see LongArraySubList#set(int, long)
	 */
	public Long set(int index, Long value) {
    	if (index < 0 || index >= size) {
    		throw new IndexOutOfBoundsException();
    	}
    	Long oldValue = longs[index];
        longs[index] = value;
        return oldValue;
	}

	/**
	 * @see LongArraySubList#clear()
	 */
	public void clear() {
		size = 0;
		longs = new long[MIN_SIZE];
	}

	/**
	 * @see LongArraySubList#size()
	 */
	public int size() {
		return size;
	}

	/**
	 * @see LongArraySubList#toArray()
	 */
	public Long [] toArray() {
		Long[] values = new Long[size];
		for(int i=0;i<size;i++) {
			values[i] = longs[i];
		}
		return values;
	}
	public long[] toLongArray() {
		return toLongArray(0, size());
	}

	public long[] toLongArray(int start, int length) {
		long [] tmparr = new long[length];
		System.arraycopy(longs,start,tmparr,0,length);
		return tmparr;
	}

    /**
     * Doubles the size of the array.
     * @param size The new capacity of the array.
     */
    private void growArray() {
    	int len = longs.length;
    	if (len == 0) {
    		longs = new long[4];
    		return;
    	}
		long [] newlongs = new long[len*2];
        System.arraycopy(longs,0,newlongs,0,len);
        longs = newlongs;
    }

    private void shrinkArray() {
    	int newsize = longs.length/2;
    	if (newsize < MIN_SIZE) {
    		return;
    	}
		long [] newlongs = new long[newsize];
        System.arraycopy(longs,0,newlongs,0,size);
        longs = newlongs;
    }

	public void reverse() {
		int half = size / 2;
		for (int i = 0, j = size - 1 ; i < half ; ++i, --j) {
			long tmp = longs[i] ;
			longs[i] = longs[j];
			longs[j] = tmp;
		}
	}


	public boolean remove(Object value) {
		if (!(value instanceof Long)) {
			return false;
		}
		long longValue = ((Long)value).longValue();
		for(int i=0;i<size;i++) {
			if (longs[i] == longValue) {
				remove(i);
				return true;
			}
		}
		return false;
	}

	public int indexOf(Object value) {
		if (!(value instanceof Long)) {
			return -1;
		}
		long longValue = ((Long)value).longValue();
		for(int i=0;i<size;i++) {
			if (longs[i] == longValue) {
				return i;
			}
		}		
		return -1;
	}
	public List<Long> subList(int startIndex, int endIndex) {
		return new LongArraySubList(this, startIndex, endIndex);
	}
	
	public boolean addAll(Collection<? extends Long> c) {
		return addAll(size(), c);
	}

	public boolean addAll(int index, Collection<? extends Long> c) {
		int newSize = size + c.size();
		long[] newValues = new long[newSize];
		System.arraycopy(longs, 0, newValues, 0, index);
		Iterator<? extends Long> it = c.iterator();
		int nextIndex = index;
		while (it.hasNext()) {
			newValues[nextIndex++] = it.next();
		}
		System.arraycopy(longs, index, newValues, nextIndex, size-index);
		longs = newValues;
		size = newSize;
		return true;
	}

	public boolean contains(Object value) {
		return indexOf(value) >= 0;
	}

	public boolean containsAll(Collection<?> c) {
		Iterator<?> it = c.iterator();
		while(it.hasNext()) {
			if (!contains(it.next())) {
				return false;
			}
		}
		return true;
	}

	public boolean isEmpty() {
		return size() == 0;
	}

	public Iterator<Long> iterator() {
		return new LongArrayListIterator(this, 0);
	}

	public int lastIndexOf(Object value) {
		if (!(value instanceof Long)) {
			return -1;
		}
		long longValue = ((Long)value).longValue();
		for(int i=size-1;i>=0;i--) {
			if (longs[i] == longValue) {
				return i;
			}
		}		
		return -1;
	}

	public ListIterator<Long> listIterator() {
		return new LongArrayListIterator(this, 0);
	}

	public ListIterator<Long> listIterator(int index) {
		return new LongArrayListIterator(this, index);
	}

	public boolean removeAll(Collection<?> c) {
		boolean changed = false;
		Iterator<?> it = c.iterator();
		while(it.hasNext()) {
			if (remove(it.next())) {
				changed = true;
			}
		}
		return changed;
	
	}

	public boolean retainAll(Collection<?> c) {
		long[] newValues = new long[longs.length];
		int newIndex = 0;
		for(int i=0;i<size;i++) {
			if (c.contains(longs[i])) {
				newValues[newIndex++] = longs[i];
			}
		}
		longs = newValues;
		boolean changed = (size == newIndex);
		size = newIndex;
		return changed;
	}
	
	static class LongArraySubList implements List<Long> {
		private int startIndex;
		private int endIndex;
		private LongArrayList backingList;
		
		LongArraySubList(LongArrayList list, int startIndex, int endIndex) {
			this.backingList = list;
			this.startIndex = startIndex;
			this.endIndex = endIndex;
		}

		public boolean add(Long value) {
			backingList.add(endIndex++, value);
			return true;
		}
		public void add(long value) {
			backingList.add(endIndex++, value);
		}

		public void add(int index, Long value) {
	    	if (index < 0 || index > (endIndex-startIndex)) {
	    		throw new IndexOutOfBoundsException();
	    	}
	    	backingList.add(startIndex+index, value);
	    	endIndex++;
		}
		public void add(int index, long value) {
	    	if (index < 0 || index > (endIndex-startIndex)) {
	    		throw new IndexOutOfBoundsException();
	    	}
	    	backingList.add(startIndex+index, value);
			endIndex++;
		}

		public Long remove(int index) {
	    	if (index < 0 || index >= (endIndex-startIndex)) {
	    		throw new IndexOutOfBoundsException();
	    	}
	    	endIndex--;
	    	return backingList.remove(startIndex+index);
		}

		public Long get(int index) {
	    	if (index < 0 || index >= (endIndex-startIndex)) {
	    		throw new IndexOutOfBoundsException();
	    	}
			return backingList.get(startIndex+index);
		}

		public void set(int index, long value) {
	    	if (index < 0 || index >= (endIndex-startIndex)) {
	    		throw new IndexOutOfBoundsException();
	    	}
	    	backingList.set(startIndex+index, value);
		}

		public void clear() {
			for(int i=startIndex;i<endIndex;i++) {
				backingList.remove(startIndex);
			}
			endIndex = startIndex;
		}

		public int size() {
			return endIndex-startIndex;
		}

		public Long[] toArray() {
			int size = size();
			Long[] values = new Long[size];
			for(int i=0;i<size;i++) {
				values[i] = get(i);
			}
			return values;
		}

		public boolean remove(Object value) {
			if (!(value instanceof Long)) {
				return false;
			}
			int size = size();
			long longValue = ((Long)value).longValue();
			for(int i=0;i<size;i++) {
				if (backingList.longs[startIndex+i] == longValue) {
					remove(i);
					return true;
				}
			}
			return false;
		}

		public int getIndex(long value) {
			for(int i=0;i<size();i++) {
				if (get(i) == value) {
					return i;
				}
			}		
			return -1;		
		}

		public boolean addAll(Collection<? extends Long> c) {
			backingList.addAll(endIndex, c);
			endIndex += c.size();
			return true;
		}

		public boolean addAll(int index, Collection<? extends Long> c) {
			backingList.addAll(startIndex+index, c);
			endIndex += c.size();
			return true;
		}

		public boolean contains(Object o) {
			return indexOf(o) >= 0;
		}

		public boolean containsAll(Collection<?> c) {
			Iterator<?> it = c.iterator();
			while(it.hasNext()) {
				if (!contains(it.next())) {
					return false;
				}
			}
			return true;
		}

		public int indexOf(Object value) {
			if (!(value instanceof Long)) {
				return -1;
			}
			long longValue = ((Long)value).longValue();
			for(int i=0;i<size();i++) {
				if (backingList.longs[startIndex+i] == longValue) {
					return i;
				}
			}		
			return -1;
		}

		public boolean isEmpty() {
			return size() == 0;
		}

		public Iterator<Long> iterator() {
			return new LongArrayListIterator(this, 0);
		}

		public int lastIndexOf(Object value) {
			if (!(value instanceof Long)) {
				return -1;
			}
			long longValue = ((Long)value).longValue();
			for(int i=size()-1;i>=0;i--) {
				if (backingList.longs[startIndex+i] == longValue) {
					return i;
				}
			}		
			return -1;
		}

		public ListIterator<Long> listIterator() {
			return new LongArrayListIterator(this, 0);
		}

		public ListIterator<Long> listIterator(int index) {
			return new LongArrayListIterator(this, index);
		}

		public boolean removeAll(Collection<?> c) {
			boolean changed = false;
			Iterator<?> it = c.iterator();
			while(it.hasNext()) {
				if (remove(it.next())) {
					changed = true;
				}
			}
			return changed;
		}

		public boolean retainAll(Collection<?> c) {
			boolean changed = false;
			Iterator<Long> it = iterator();
			while(it.hasNext()) {
				Object value = it.next();
				if (!c.contains(value)) {
					it.remove();
					changed = true;
				}
			}
			return changed;
		}

		public Long set(int index, Long element) {
			if (index < 0 || index >= size()) {
				throw new IllegalArgumentException();
			}
			Long oldValue = get(index);
			backingList.set(startIndex+index, element);
			return oldValue;
		}

		public List<Long> subList(int fromIndex, int toIndex) {
			return new LongArraySubList(backingList,startIndex+fromIndex, startIndex+toIndex);
		}

		@SuppressWarnings("unchecked") // unchecked casts
		public <T> T[] toArray(T[] a) {
	        if (a.length < size()) {
	            a = (T[])java.lang.reflect.Array.newInstance(a.getClass().getComponentType(), size());
	        }
			for(int i=0;i<size();i++) {
				a[i] = (T)get(i);
			}
	        if (a.length > size()) {
	            a[size()] = null;
	        }
	        return a;
		}

	}

	@SuppressWarnings("unchecked") // unchecked cast
	public <T> T[] toArray(T[] a) {
        if (a.length < size) {
            a = (T[])java.lang.reflect.Array.newInstance(a.getClass().getComponentType(), size);
        }
		for(int i=0;i<size;i++) {
			Long value = longs[i];
			a[i] = (T)value;
		}
        if (a.length > size) {
            a[size] = null;
        }
        return a;
	}
	public Long [] toArray(Long[] a) {
		Long[] values = new Long[size];
		for(int i=0;i<size;i++) {
			values[i] = longs[i];
		}
		return values;
	}

}
class LongArrayListIterator implements ListIterator<Long> {
	int nextIndex;
	int lastReturnedIndex = -1;
	List<Long> list;
	
	public LongArrayListIterator(List<Long> list, int startIndex) {
		this.list = list;
		this.nextIndex = startIndex;
	}
	
	public void add(Long o) {
		list.add(nextIndex, o);
	}

	public boolean hasNext() {
		return nextIndex < list.size();
	}

	public boolean hasPrevious() {
		return nextIndex > 0;
	}

	public Long next() {
		if (!hasNext()) {
			throw new NoSuchElementException();
		}
		lastReturnedIndex = nextIndex;
		return list.get(nextIndex++);
	}

	public int nextIndex() {
		return nextIndex;
	}

	public Long previous() {
		if (!hasPrevious()) {
			throw new NoSuchElementException();
		}
		lastReturnedIndex = nextIndex -1;
		return list.get(--nextIndex);
	}

	public int previousIndex() {
		return nextIndex-1;
	}

	public void remove() {
		if (lastReturnedIndex == -1) {
			throw new IllegalStateException();
		}
		list.remove(lastReturnedIndex);
		if (nextIndex > lastReturnedIndex) {
			nextIndex--;
		}
		lastReturnedIndex = -1;
	}

	public void set(Long o) {
		if (lastReturnedIndex == -1) {
			throw new IllegalStateException();
		}
		list.set(lastReturnedIndex, o);
	}
	
}
