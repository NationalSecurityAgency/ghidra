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
package ghidra.program.util;

/**
 * Interface to define event types and the method to generate an
 * event within Program.
 */
public interface DataTypeArchiveChangeManager {

    // event types

    ////////////////////////////////////////////////////////////////////////////
    //
    //                        CATEGORY and DATA
    //
    ////////////////////////////////////////////////////////////////////////////

    /**
     * Category was added.
     */
    public static final int DOCR_CATEGORY_ADDED = 100;

    /**
     * Category was removed.
     */
    public static final int DOCR_CATEGORY_REMOVED = 101;

    /**
     * Category was renamed.
     */
    public static final int DOCR_CATEGORY_RENAMED = 102;

    /**
     * Category was moved.
     */
    public static final int DOCR_CATEGORY_MOVED = 103;

    /**
     * Data type was added to a category.
     */
    public static final int DOCR_DATA_TYPE_ADDED = 104;

    /**
     * Data type was removed from a category.
     */
    public static final int DOCR_DATA_TYPE_REMOVED = 105;

    /**
     * Data Type was renamed.
     */
    public static final int DOCR_DATA_TYPE_RENAMED = 106;

    /**
     * Data type was moved to another category.
     */
    public static final int DOCR_DATA_TYPE_MOVED = 107;

    /**
     * Data type was updated.
     */
    public static final int DOCR_DATA_TYPE_CHANGED = 108;
    
    /**
     * The settings on a data type were updated.
     */
    public static final int DOCR_DATA_TYPE_SETTING_CHANGED = 109;

    /**
     * Data type was replaced in a category.
     */
    public static final int DOCR_DATA_TYPE_REPLACED = 110;
    
	/**
	 * A custom format for a data type was added.
	 */	
	public final static int DOCR_CUSTOM_FORMAT_ADDED = 163;
	
	/**
	 * A custom format for a data type was removed.
	 */
	public final static int DOCR_CUSTOM_FORMAT_REMOVED = 164;
	
	////////////////////////////////////////////////////////////////////////////
	/**
     * Mark the state of a Data Type Archive as having changed and generate
     * the event of the specified type.  Any or all parameters may be null.
     * @param type event type
     * @param oldValue original value or an Object that is related to
     * the event
     * @param newValue new value or an Object that is related to the
     * the event
     */		
	public void setChanged(int type, Object oldValue, Object newValue);
	 	
    /**
     * Mark the state of a Data Type Archive as having changed and generate
     * the event of the specified type.  Any or all parameters may be null.
     * @param type event type
     * @param affectedObj object that is the subject of the event
     * @param oldValue original value or an Object that is related to
     * the event
     * @param newValue new value or an Object that is related to the
     * the event
     */
    public void setObjChanged(int type, 
    						Object affectedObj, Object oldValue, Object newValue);
    
}
