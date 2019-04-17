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
package ghidra.feature.vt.api.impl;

/**
 * Interface to define event types and the method to generate an
 * event within Version Tracking.
 */
public interface VTChangeManager {

	// event types

	////////////////////////////////////////////////////////////////////////////
	//
	//                           MATCHES
	//
	////////////////////////////////////////////////////////////////////////////

	public static final int DOCR_VT_MATCH_SET_ADDED = 1010;

	////////////////////////////////////////////////////////////////////////////
	//
	//                           MATCHES
	//
	////////////////////////////////////////////////////////////////////////////

	/**
	 * The status of a match item in the version tracking results has changed.
	 */

	public static final int DOCR_VT_ASSOCIATION_STATUS_CHANGED = 1021;
	public static final int DOCR_VT_ASSOCIATION_MARKUP_STATUS_CHANGED = 1027;

	public static final int DOCR_VT_MATCH_ADDED = 1022;

	public static final int DOCR_VT_MATCH_DELETED = 1023;

	public static final int DOCR_VT_MATCH_TAG_CHANGED = 1024;

	public static final int DOCR_VT_ASSOCIATION_ADDED = 1025;

	public static final int DOCR_VT_ASSOCIATION_REMOVED = 1026;

	////////////////////////////////////////////////////////////////////////////
	//
	//                              MARKUP ITEMS
	//
	////////////////////////////////////////////////////////////////////////////

	/**
	 * The status of a version tracking mark-up item has changed.
	 */
	public static final int DOCR_VT_MARKUP_ITEM_STATUS_CHANGED = 1030;

	/**
	 * The destination address of a version tracking mark-up item has changed.
	 */
	public static final int DOCR_VT_MARKUP_ITEM_DESTINATION_CHANGED = 1031;

	public static final int DOCR_VT_TAG_ADDED = 1040;

	public static final int DOCR_VT_TAG_REMOVED = 1041;

	public static final int DOCR_VT_VOTE_COUNT_CHANGED = 1050;

	/**
	 * Mark the state of a Version Tracking item as having changed and generate
	 * the event of the specified type.  Any or all parameters may be null.
	 * @param type event type
	 * @param oldValue original value or an Object that is related to the event.
	 * @param newValue new value or an Object that is related to the event.
	 */
	public void setChanged(int type, Object oldValue, Object newValue);

	/**
	 * Mark the state of a Version Tracking item as having changed and generate
	 * the event of the specified type.  Any or all parameters may be null.
	 * @param type event type
	 * @param affectedObj the version tracking object that was affected by the change.
	 * @param oldValue original value or an Object that is related to the event.
	 * @param newValue new value or an Object that is related to the event.
	 */
	public void setObjectChanged(int type, Object affectedObject, Object oldValue, Object newValue);

}
