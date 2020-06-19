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
package ghidra.util.prop;

import java.io.*;
import java.util.HashMap;
import java.util.Map;

import ghidra.util.LongIterator;
import ghidra.util.datastruct.NoSuchIndexException;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.NoValueException;

/**
 * Base class for managing properties that are accessed by an index. Property
 * values are determined by the derived class.
 */
public abstract class PropertySet implements Serializable {
	private final static long serialVersionUID = 1;
	protected static final NoValueException noValueException = new NoValueException();
	private final static int DEFAULT_NUMBER_PAGE_BITS = 12;
	private final static int MIN_NUMBER_PAGE_BITS = 8;
	private final static int MAX_NUMBER_PAGE_BITS = 15;	// must be kept less than
														// size of a short

	private String name;
	protected PropertyPageIndex propertyPageIndex; // table of pageIDs
	private int numPageBits; // number of bits from long used as page offset
	private long pageMask; // a mask for the offset bits, i.e. has a 1 if and only if
							// the bit is part of the offset
	protected short pageSize; // max elements in each page
	protected int numProperties;
	private Map<Long, PropertyPage> ht;
	private Class<?> objectClass;

	protected PropertySet(String name, Class<?> objectClass) {
		this(name, DEFAULT_NUMBER_PAGE_BITS, objectClass);
	}

	/**
	 * Construct a PropertyMap
	 * @param name property name
	 * @param numPageBits number of bits to use for the
	 * 		page size. Will be set to be at least 8 and no
	 *		more than 15.
	 */
	protected PropertySet(String name, int numPageBits, Class<?> objectClass) {
		this.objectClass = objectClass;
		ht = new HashMap<>();

		this.name = name;
		if (numPageBits > MAX_NUMBER_PAGE_BITS) {
			numPageBits = MAX_NUMBER_PAGE_BITS;
		}
		else if (numPageBits < MIN_NUMBER_PAGE_BITS) {
			numPageBits = MIN_NUMBER_PAGE_BITS;
		}
		this.numPageBits = numPageBits;
		// compute the page mask
		pageMask = -1L;
		pageMask = pageMask >>> (64 - numPageBits); // 64 = size of long

		pageSize = (short) (pageMask + 1);
		propertyPageIndex = new PropertyPageIndex();
	}

	/**
	 * Returns the size (in bytes) of the data that is stored in this property
	 * set.
	 * @return the size (in bytes) of the data that is stored in this property
	 * set.
	 */
	public abstract int getDataSize();

	/**
	 * Get the name for this property manager.
	 */
	public synchronized String getName() {
		return name;
	}

	/**
	 * Returns property object class associated with this set.
	 */
	public Class<?> getObjectClass() {
		return objectClass;
	}

	protected PropertyPage getPage(long pageId) {
		return ht.get(pageId);
	}

	protected PropertyPage getOrCreatePage(long pageID) {
		PropertyPage page = getPage(pageID);
		if (page == null) {
			page = new PropertyPage(pageSize, pageID, getDataSize(), objectClass);
			ht.put(pageID, page);
			propertyPageIndex.add(pageID);
		}
		return page;
	}

	/**
	 * Given two indices it indicates whether there is an index in
	 * that range (inclusive) having the property.<p>
	 * @param start	the start of the index range.
	 * @param end the end of the index range.
	 *
	 * @return boolean true if at least one index in the range
	 * has the property, false otherwise.
	 */
	public boolean intersects(long start, long end) {
		if (hasProperty(start)) {
			return true;
		}
		try {
			long index = this.getNextPropertyIndex(start);
			if (index <= end) {
				return true;
			}
		}
		catch (NoSuchIndexException e) {
			return false;
		}
		return false;
	}

	/**
	 * Removes all property values within a given range.
	 * @param start begin range
	 * @param end end range, inclusive
	 * @return true if any property value was removed; return
	 * 		false otherwise.
	 */
	public synchronized boolean removeRange(long start, long end) {

		boolean status = false;
		// go from start to end
		// get the page starting at start
		// get page start index and end index
		//    subtract page.getSize() from numProperties
		//    remove the entire page
		//    increment start by size of page
		// else
		//    for (i<endofPage; start++)
		//       call slow remove(index);

		while (start <= end) {
			// get page containing start
			long pageID = getPageID(start);
			short offset = getPageOffset(start);

			PropertyPage page = getPage(pageID);

			if (page == null) {
				long nextPageId = propertyPageIndex.getNext(pageID);
				if (nextPageId < 0) {
					break;
				}
				start = nextPageId << numPageBits;
				continue;
			}

			// if start is beginning of page && end of page is still less than start
			if (offset == 0 && (pageSize + start) <= end) {

				// decrement # properties on a page
				this.numProperties -= page.getSize();

				// remove the entire page
				ht.remove(pageID);
				propertyPageIndex.remove(pageID);

				status = true;
				long nextPageId = propertyPageIndex.getNext(pageID);
				start = nextPageId << numPageBits;
			}
			else {
				// start at offset, and remove each property
				for (; offset < pageSize && start <= end; offset++, start++) {
					status |= removeFromPage(page, pageID, offset);
				}
			}
		}

		return status;
	}

	/**
	 * Remove the property value at the given index.
	 * @return true if the property value was removed, false
	 *   otherwise.
	 * @param index the long representation of an address.
	 */
	public synchronized boolean remove(long index) {
		long pageID = getPageID(index);
		short offset = getPageOffset(index);

		PropertyPage page = getPage(pageID);

		return removeFromPage(page, pageID, offset);
	}

	/**
	 * Remove the property on page at offset.  If Page is now empty, remove it.
	 */
	private boolean removeFromPage(PropertyPage page, long pageID, short offset) {
		if (page != null) {

			boolean removed = page.remove(offset);
			if (removed) {
				numProperties--;
			}

			if (page.isEmpty()) {
				ht.remove(pageID);
				propertyPageIndex.remove(pageID);
			}
			return removed;
		}
		return false;
	}

	/**
	 * returns whether there is a property value at index.
	 * @param index the long representation of an address.
	 */
	public synchronized boolean hasProperty(long index) {
		PropertyPage page = getPage(getPageID(index));
		if (page == null) {
			return false;
		}
		return page.hasProperty(getPageOffset(index));
	}

	/**
	 * Get the next index where the property value exists.
	 * @param index the address from which to begin the search (exclusive).
	 * @throws NoSuchIndexException thrown if there is no address with
	 *   a property value after the given address.
	 */
	public synchronized long getNextPropertyIndex(long index) throws NoSuchIndexException {
		long pageID = getPageID(index);
		short offset = getPageOffset(index);
		PropertyPage page = getPage(pageID);

		if (page != null) {
			short nextOffset = page.getNext(offset);

			if (nextOffset >= 0) {
				return getIndex(pageID, nextOffset);
			}
		}

		pageID = propertyPageIndex.getNext(pageID);

		if (pageID >= 0) {
			page = getPage(pageID);
			if (page != null) {
				short nextOffset = page.getFirst();
				if (nextOffset < 0) {
					throw new AssertException(
						"Page (" + pageID +
							") exists but there is no 'first' offset");
				}
				return getIndex(pageID, nextOffset);
			}
		}
		throw NoSuchIndexException.noSuchIndexException;
	}

	/**
	 * Get the previous index where a property value exists.
	 * @param index the long representation of an address from which
	 * 		to begin the search (exclusive).
	 * @throws NoSuchIndexException when there is no index
	 * 		with a property value before the given address.
	 */
	public synchronized long getPreviousPropertyIndex(long index) throws NoSuchIndexException {

		long pageID = getPageID(index);
		short offset = getPageOffset(index);

		PropertyPage page = getPage(pageID);

		if (page != null) {
			short prevOffset = page.getPrevious(offset);
			if (prevOffset >= 0) {
				return getIndex(pageID, prevOffset);
			}
		}

		pageID = propertyPageIndex.getPrevious(pageID);

		if (pageID >= 0) {
			page = getPage(pageID);
			if (page != null) {
				short prevOffset = page.getLast();
				if (prevOffset < 0) {
					throw new AssertException(
						"Page (" + pageID +
							") exists but there is no 'last' offset");
				}
				return getIndex(pageID, prevOffset);
			}
		}

		throw NoSuchIndexException.noSuchIndexException;
	}

	/**
	 * Get the first index where a property value exists.
	 * @throws NoSuchIndexException when there is no property value for any index.
	 */
	public synchronized long getFirstPropertyIndex() throws NoSuchIndexException {
		if (hasProperty(0)) {
			return 0;
		}
		return getNextPropertyIndex(0);
	}

	/**
	 * Get the last index where a property value exists.
	 * @exception NoSuchIndexException
	 *                   thrown if there is no address having the property value.
	 */
	public synchronized long getLastPropertyIndex() throws NoSuchIndexException {
		// -1 should be the highest possible address
		if (hasProperty(-1)) {
			return -1;
		}
		return getPreviousPropertyIndex(-1);
	}

	/**
	 * Get the number of properties in the set.
	 * @return the number of properties
	 */
	public int getSize() {
		return numProperties;
	}

	/**
	 * Extract the page ID from the given index.
	 * @param index the long representation of an address.
	 */
	protected final long getPageID(long index) {
		return index >>> numPageBits;

	}

	/**
	 * Extract the page offset from the given index.
	 * @param index the long representation of an address.
	 */
	protected final short getPageOffset(long index) {
		return (short) (index & pageMask);
	}

	/**
	 * Create an index from the pageID and the offset in the page.
	 * @return the long representation of an address.
	 */
	protected final long getIndex(long pageID, short offset) {
		return (pageID << numPageBits) | offset;
	}

	/**
	 * Move the range of properties to the newStart index.
	 * @param start the beginning of the property range to move
	 * @param end the end of the property range to move
	 * @param newStart the new beginning of the property range after the move
	 */
	public void moveRange(long start, long end, long newStart) {
		if (newStart < start) {
			long clearSize = end - start + 1;
			long offset = start - newStart;
			if (offset < clearSize) {
				clearSize = offset;
			}
			removeRange(newStart, newStart + clearSize - 1);
			LongIterator it = getPropertyIterator(start, end);
			while (it.hasNext()) {
				long index = it.next();
				moveIndex(index, index - offset);
			}
		}
		else {
			long clearSize = end - start + 1;
			long offset = newStart - start;
			if (offset < clearSize) {
				clearSize = offset;
			}
			if (newStart > end) {
				removeRange(newStart, newStart + clearSize - 1);
			}
			else {
				removeRange(end + 1, end + clearSize);
			}

			LongIterator it = getPropertyIterator(end + 1);
			while (it.hasPrevious()) {
				long index = it.previous();
				if (index < start) {
					break;
				}
				moveIndex(index, index + offset);
			}
		}
	}

	protected abstract void moveIndex(long from, long to);

	protected abstract void saveProperty(ObjectOutputStream oos, long addr)
			throws IOException;

	protected abstract void restoreProperty(ObjectInputStream ois, long addr)
			throws IOException, ClassNotFoundException;

	/**
	 * Creates an iterator over all the indexes that have this property within
	 * the given range.
	 *
	 * @param start The start address to search
	 * @param end The end address to search
	 * @return LongIterator Iterator over indexes that have properties.
	 */
	public LongIterator getPropertyIterator(long start, long end) {
		return new LongIteratorImpl(this, start, end);
	}

	/**
	 * Creates an iterator over all the indexes that have this property within
	 * the given range.
	 * 
	 * @param start The start address to search
	 * @param end The end address to search
	 * @param atStart indicates if the iterator should begin at the start
	 * address, otherwise it will start at the last address.  Set this flag to
	 * false if you want to iterate backwards through the properties.
	 * @return LongIterator Iterator over indexes that have properties.
	 */
	public LongIterator getPropertyIterator(long start, long end, boolean atStart) {
		return new LongIteratorImpl(this, start, end, atStart);
	}

	/**  
	 * Returns an iterator over the indices having the given property
	 * value.
	 */
	public LongIterator getPropertyIterator() {
		return new LongIteratorImpl(this);
	}

	/** 
	 * Returns an iterator over the indices having the given property
	 * value.
	 * @param start the starting index for the iterator.
	 */
	public LongIterator getPropertyIterator(long start) {
		return new LongIteratorImpl(this, start, true);
	}

	/** 
	 * Returns an iterator over the indices having the given property
	 * value.
	 * @param start the starting index for the iterator.
	 * @param before if true the iterator will be positioned before the start value.
	 */
	public LongIterator getPropertyIterator(long start, boolean before) {
		return new LongIteratorImpl(this, start, before);
	}

	/**
	 * Saves all property values between start and end to the output stream
	 * @param oos the output stream
	 * @param start the first index in the range to save.
	 * @param end the last index in the range to save.
	 * @throws IOException if an I/O error occurs on the write.
	 */
	public void saveProperties(ObjectOutputStream oos, long start, long end)
			throws IOException {

		oos.writeLong(start);
		oos.writeLong(end);
		if (hasProperty(start)) {
			oos.writeByte(1);
			oos.writeLong(start);
			saveProperty(oos, start);
		}
		try {
			long index = start;
			while ((index = getNextPropertyIndex(index)) <= end) {
				oos.writeByte(1);
				oos.writeLong(index);
				saveProperty(oos, index);
			}
		}
		catch (NoSuchIndexException e) {
		}
		oos.writeByte(0);
	}

	/**
	 * Restores all the properties from the input stream.  Any existing
	 * properties will first be removed.
	 * @param ois the input stream.
	 * @throws IOException if I/O error occurs.
	 * @throws ClassNotFoundException if the a class cannot be determined for
	 * the property value.
	 */
	public void restoreProperties(ObjectInputStream ois)
			throws IOException, ClassNotFoundException {
		long start = ois.readLong();
		long end = ois.readLong();
		this.removeRange(start, end);
		while (ois.readByte() != 0) {
			long index = ois.readLong();
			restoreProperty(ois, index);
		}
	}

	/**
	 * Based upon the type of property manager that this is, the appropriate
	 * visit() method will be called within the PropertyVisitor.
	 * @param visitor object implementing the PropertyVisitor interface.
	 * @param addr the address of where to visit (get) the property.
	 */
	public abstract void applyValue(PropertyVisitor visitor, long addr);

}
