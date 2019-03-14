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
package ghidra.program.model.address;

import ghidra.util.datastruct.NoSuchIndexException;
import ghidra.util.prop.ObjectPropertySet;

import java.io.Serializable;


/**
 * <CODE>AddressObjectMap</CODE> maintains a mapping between addresses in the program
 * and Objects that have been discovered.
 * <P>
 * AddressObjectMap uses an ObjectPropertySet to track which addresses belong to
 * which Objects. If a range <CODE>[addr1,addr2]</CODE> is assigned to a Object
 * with id <CODE>ID</CODE> then <CODE>-ID</CODE> will be placed as the property value at
 * <CODE>addr1</CODE> and <CODE>ID</CODE> will be placed at <CODE>addr2</CODE>.
 * In other words AddressObjectMap marks the beginning of a range belonging to an
 * Object with its id (a positive number) and the end with its
 * id (a negative number). A single address "range" will just have one entry
 * which will contain <CODE>-objID</CODE>.
 *
 * It is important to realize that the current implementation of this cache,
 * an address can only belong in one Object.  This could have bad effects
 * for BlockModels where code can exist in more than one Object.  If this
 * is to be used in that case, one must not just clear an area before adding in
 * a range of addresses.  You would need to check if there is anything already
 * defined and store a new index in those places that would represent a multi-block
 * location.
 *
 * An AddressObjectMap instance should only be used to map to addresses contained within
 * a single program.  The map should be discard if any changes 
 * are made to that programs address map (e.g., removing or renaming overlay spaces).
 */

public class AddressObjectMap {
    
    private AddressMapImpl addrMap = new AddressMapImpl();
    private ObjectPropertySet objMarkers = new ObjectPropertySet("AddressObjectMap");
    
    private static final Object [] emptyArray = new Object[0];

    /**
     * Creates a new <CODE>AddressObjectMap</CODE> object.
     */
    public AddressObjectMap() {
    }

    /**
     *  Get the objs associated with the given address.
     * @param addr the address at which to get objects.
     * @return an array of objects at the given address.
     */
    public Object[] getObjects(Address addr) {

        Object objarray[] = getObj(addrMap.getKey(addr));
        return objarray;
    }

	/**
	 * Associates the given object with the given set of addresses
	 * @param obj the object to associate
	 * @param set the set of address to be associated with the object.
	 */
    public void addObject(Object obj, AddressSetView set) {
        // map the obj into a new index

        // iterate through ranges defined for obj
        AddressRangeIterator iter = set.getAddressRanges();
        while (iter.hasNext()) {
            AddressRange range = iter.next();
            addObject(obj, range.getMinAddress(), range.getMaxAddress());
        }
    }

    
	/**
	 * Associates the given object with the given range of addresses
	 * @param obj the object to associate
	 * @param startAddr the first address in the range
	 * @param endAddr the last address in the range
	 */
    public void addObject(Object obj, Address startAddr, Address endAddr) {
        long start = addrMap.getKey(startAddr);
        long end = addrMap.getKey(endAddr);
        addRange(obj, start, end);
        coalesceRange(start,end);
    }
    
	/**
	 * Removes any association with the object and the addresses in the given address set.
	 * @param obj the object to remove
	 * @param set the set of address from which to remove the object.
	 */
    public void removeObject(Object obj, AddressSetView set) {
        AddressRangeIterator iter = set.getAddressRanges();
        while (iter.hasNext()) {
            AddressRange range = iter.next();
            removeObject(obj, range.getMinAddress(), range.getMaxAddress());
        }
    }
    
    /**
     * Removes any association with the given object and the given range of addresses.
     * @param obj the object to remove from associations in the given range.
     * @param startAddr the first address in the range.
     * @param endAddr the last address in the range.
     */
    public void removeObject(Object obj, Address startAddr, Address endAddr) {
        long start = addrMap.getKey(startAddr);
        long end = addrMap.getKey(endAddr);
        removeRange(obj, start, end);
        coalesceRange(start, end);
    }
    

    /**
     * Gets the list of objects associated with the given address.
     * @param longAddr the long value of the address.
     *
     * @return an array of objects that have been associated with the given address
     */
    private Object[] getObj(long longAddr) {
        Mark mark;
        if(objMarkers.hasProperty(longAddr)) {
            mark = getMark(longAddr);
        }
        else {
            try {
                long next = objMarkers.getNextPropertyIndex(longAddr);
                mark = getMark(next);
                if (mark.type == Mark.START || mark.type == Mark.SINGLE) {
                    return emptyArray;
                }
            }
            catch(NoSuchIndexException e2) {
                return emptyArray;
            }
        }
        return mark.getObj();
    }

    private Mark getMark(long index) {
        return (Mark)objMarkers.getObject(index);
    }

    /**
     * Adds a range to a object.
     * Assumes that the range has already been cleared.
     * <P>
     * @param range the range being added.
     * @param objID the id of the object the range is being
     * added to.
     */
    private void addRange(Object obj, long start, long end) {
        try {
            long next;
            if (objMarkers.hasProperty(start)) {
                next = start;
            }
            else {
                next = objMarkers.getNextPropertyIndex(start);
            }

            while (start <= end) {
                // find the thing at or after
                Mark mark = getMark(next);

                if (mark.type == Mark.END) {
                    markEnd(start-1, mark.obj);
                    markStart(start, mark.obj);
                    next = start;
                }
                else if (start == next) {
                    if (mark.type == Mark.SINGLE) {
                        mark.add(obj);
                        start = start+1;
                    }
                    else { // type == Mark.START
                        next = objMarkers.getNextPropertyIndex(next);
                        start = doSplit(obj,start,next,end) + 1;
                    }
                    next = objMarkers.getNextPropertyIndex(next);
                }
                else if (start < next && next <= end) {
                    // add in start to next -1
                    markRange(start, next-1, obj);
                    start = next;
                }
                else if (next > end) {
                        break;
                }
            }
        }
        catch(NoSuchIndexException e) {
        }
        if (start <= end) {
            markRange(start, end, obj);
        }

    }


    private void markRange(long start, long end, Object obj) {
        if (start == end) {
            objMarkers.putObject(start, new Mark(obj, Mark.SINGLE));
        } else {
            objMarkers.putObject(start, new Mark(obj, Mark.START));
            objMarkers.putObject(end, new Mark(obj, Mark.END));
        }
    }

    private void markStart(long addr, Object obj) {
        // if already a begin there, make a SINGLE
        // else store mark
        Mark mark = getMark(addr);
        if (mark != null && mark.type == Mark.END) {
            mark = new Mark(obj, Mark.SINGLE);
        } else {
            mark = new Mark(obj, Mark.START);
        }
        objMarkers.putObject(addr, mark);
    }

    private void markEnd(long addr, Object obj) {
        // if already a begin there, make a SINGLE
        // else store mark
        Mark mark = getMark(addr);
        if (mark != null && mark.type == Mark.START) {
            mark = new Mark(obj, Mark.SINGLE);
        } else {
            mark = new Mark(obj, Mark.END);
        }
        objMarkers.putObject(addr, mark);
    }

    private long doSplit(Object obj, long start, long next, long end) {
        Mark existMark = getMark(start);
        if (next > end) {
            // add a new begin end
            markStart(end+1, existMark.obj);
        }
        existMark.add(obj);
        long splitEnd = Math.min(next, end);
        markEnd(splitEnd, existMark.obj);
        return splitEnd;
    }

    private long doDeleteSplit(Object obj, long start, long next, long end) {
        Mark existMark = getMark(start);
        if (next > end) {
            markStart(end+1, existMark.obj);
            existMark.remove(obj);
            if (existMark.isEmpty()) {
                objMarkers.remove(start);
            }
            else {
                markEnd(end, existMark.obj);
            }
            return end;
        }
        existMark.remove(obj);
        if (existMark.isEmpty()) {
            objMarkers.remove(start);
            objMarkers.remove(next);
        } else {
            Mark endMark = getMark(next);
            endMark.remove(obj);
        }
        return next;
    }

    /**
     * Removes a range from a object.
     * <P>
     * @param range the range being removed.
     * @param objID the id of the object it is being
     * removed from.
     */
    private void removeRange(Object obj, long start, long end) {
        try {
            long next;
            if (objMarkers.hasProperty(start)) {
                next = start;
            }
            else {
                next = objMarkers.getNextPropertyIndex(start);
            }

            while (start <= end) {
                // find the thing at or after
                Mark mark = getMark(next);

                if (mark.type == Mark.END) {
                    if (mark.contains(obj)) {
                        markEnd(start-1, mark.obj);
                        markStart(start, mark.obj);
                        next = start;
                    } else {
                        start = next;
                    }
                }
                else if (start == next) {
                    if (mark.type == Mark.SINGLE) {
                        mark.remove(obj);
                        if (mark.isEmpty()) {
                            objMarkers.remove(start);
                        }
                        start = start+1;
                    }
                    else if (mark.contains(obj)) { // type == Mark.START
                        next = objMarkers.getNextPropertyIndex(next);
                        start = doDeleteSplit(obj,start,next,end) + 1;
                    }
                    next = objMarkers.getNextPropertyIndex(next);
                }
                else if (start < next && next <= end) {
                    start = next;
                }
                else if (next > end) {
                        break;
                }
            }
        }
        catch(NoSuchIndexException e) {
        }
    }
    private void coalesceRange(long start, long end) {
        try {
            while (start <= end) {
                coalesce(start);
                start = objMarkers.getNextPropertyIndex(start);
            }
        }catch(NoSuchIndexException e) {
        }
    }

    private void coalesce(long addr) {
        if (addr > 0) {
            checkCoalese(addr-1, addr);
        }
        if (addr < Long.MAX_VALUE) {
            checkCoalese(addr, addr+1);
        }
    }

    private void checkCoalese(long first, long second) {
        Mark fMark = getMark(first);
        Mark sMark = getMark(second);
        if (fMark == null || sMark == null) {
            return;
        }
        if (!fMark.containsSameObjects(sMark)) {
            return;
        }

        if (fMark.type == Mark.END && sMark.type == Mark.START) {
            objMarkers.remove(first);
            objMarkers.remove(second);
        }
        else if (fMark.type == Mark.END && sMark.type == Mark.SINGLE) {
            objMarkers.remove(first);
            objMarkers.putObject(second, fMark);
        }
        else if (fMark.type == Mark.SINGLE && sMark.type == Mark.SINGLE) {
            objMarkers.putObject(first,new Mark(fMark.obj,Mark.START));
            objMarkers.putObject(second,new Mark(fMark.obj,Mark.END));
            markStart(first,fMark.obj);
            markEnd(second,fMark.obj);
        }
        else if (fMark.type == Mark.SINGLE && sMark.type == Mark.START) {
            objMarkers.remove(second);
            objMarkers.putObject(first,sMark);
        }
    }
}

class Mark implements Serializable {
    private final static long serialVersionUID = 1;
    
    static final int START = 1;
    static final int END = 2;
    static final int SINGLE = 3;

    private final static Object emptyArray[] = new Object[0];

    Object obj;
    int type;

    Mark(Object obj, int type){
        this.obj = obj;
        this.type = type;
    }

    void add(Object addObj) {
        if (contains(addObj)) {
            return;
        }
        Object[] bigArr;
        if (obj instanceof Object[]) {
            // generate bigger array, put old/new in it
            Object[] extArr = (Object []) obj;
            bigArr = new Object[extArr.length+1];
            System.arraycopy(extArr,0,bigArr,0,extArr.length);
            bigArr[extArr.length] = addObj;
        } else {
            bigArr = new Object[2];
            bigArr[0] = obj;
            bigArr[1] = addObj;
        }
        obj = bigArr;
    }

    boolean contains(Object testObj) {
        if (obj == null) {
            return false;
        }
        if (obj.equals(testObj)) {
            return true;
        }
        if (obj instanceof Object[]) {
            Object[] objArray = (Object[])obj;
            for(int i=0;i<objArray.length;i++) {
                if (objArray[i].equals(testObj)) {
                    return true;
                }
            }
        }
        return false;
    }
    boolean containsSameObjects(Mark mark) {
        if (obj == mark) {
            return true;
        }
        if ((obj == null) || (mark.obj == null)) {
            return false;
        }
        else if (obj.equals(mark.obj)) {
            return true;
        }
        else if ((obj instanceof Object[]) && (mark.obj instanceof Object[])) {
            Object[] array1 = (Object[])obj;
            Object[] array2 = (Object[])mark.obj;
            if (array1.length == array2.length) {
                for(int i=0;i<array1.length;i++) {
                    if (!array1[i].equals(array2[i])) {
                        return false;
                    }
                }
                return true;
            }
        }
        else if (obj instanceof Object[]) {
            Object[] array = (Object[])obj;
            return (array.length == 1) && (array[0].equals(mark.obj));
        }
        else if (mark.obj instanceof Object[]) {
            Object[] array = (Object[])mark.obj;
            return (array.length == 1) && (array[0].equals(obj));
        }
        return false;
    }


    boolean isEmpty() {
        if (obj == null) {
            return true;
        }
        if (obj instanceof Object[]) {
            if (((Object[])obj).length == 0) {
                return true;
            }
        }
        return false;
    }
    void remove(Object removeObj) {
        if (obj == null) {
            return;
        }
        if (obj.equals(removeObj)) {
            obj = null;
            return;
        }
        if (obj instanceof Object[]) {
            Object[] objArray = (Object[])obj;
            for(int i=0;i<objArray.length;i++) {
                if (objArray[i].equals(removeObj)) {
                    Object[] newArray = new Object[objArray.length-1];
                    int pos = 0;
                    for(int j=0;j<objArray.length;j++) {
                        if (j != i) {
                            newArray[pos++] = objArray[j];
                        }
                    }
                    obj = newArray;
                }
            }
        }

    }


    Object [] getObj() {

        if (obj instanceof Object[]) {
            return (Object []) obj;
        }
        if (obj == null) {
            return emptyArray;
        }
        Object[] objarray = new Object[1];
        objarray[0] = obj;

        return objarray;
    }
}

