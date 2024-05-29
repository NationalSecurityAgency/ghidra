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
package ghidra.feature.vt.api.impl;

import static ghidra.feature.vt.api.impl.VTEvent.*;

/**
 * Interface to define event types and the method to generate an
 * event within Version Tracking.
 * <P>
 * Note: Previously (before 11.1), VTEvent change event types were defined in this file as
 * integer constants. Event ids have since been converted to enum types. The defines in this file  
 * have been converted to point to the new enum values to make it easier to convert to this new way  
 * and to clearly see how the old values map to the new enums. In future releases, these defines 
 * will be removed.
 */
public interface VTChangeManager {

	////////////////////////////////////////////////////////////////////////////
	//
	//                Deprecated version tracking event ids
	//
	////////////////////////////////////////////////////////////////////////////

	/**
	 * A version tracking match set was added
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final VTEvent DOCR_VT_MATCH_SET_ADDED = MATCH_SET_ADDED;

	/**
	 * The association status of a match item in the version tracking results has changed
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final VTEvent DOCR_VT_ASSOCIATION_STATUS_CHANGED = ASSOCIATION_STATUS_CHANGED;

	/**
	 * The markup status of a match item in the version tracking results has changed
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final VTEvent DOCR_VT_ASSOCIATION_MARKUP_STATUS_CHANGED =
		ASSOCIATION_MARKUP_STATUS_CHANGED;

	/**
	 * A match result was added
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final VTEvent DOCR_VT_MATCH_ADDED = MATCH_ADDED;

	/**
	 * A match result was deleted
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final VTEvent DOCR_VT_MATCH_DELETED = MATCH_DELETED;

	/**
	 * The tag for a match was changed
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final VTEvent DOCR_VT_MATCH_TAG_CHANGED = MATCH_TAG_CHANGED;

	/**
	 * A version tracking association was added
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final VTEvent DOCR_VT_ASSOCIATION_ADDED = ASSOCIATION_ADDED;

	/**
	 * A version tracking association was removed
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final VTEvent DOCR_VT_ASSOCIATION_REMOVED = ASSOCIATION_REMOVED;

	/**
	 * A markup item status was changed
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final VTEvent DOCR_VT_MARKUP_ITEM_STATUS_CHANGED = MARKUP_ITEM_STATUS_CHANGED;

	/**
	 * A markup item's destination changed
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final VTEvent DOCR_VT_MARKUP_ITEM_DESTINATION_CHANGED =
		MARKUP_ITEM_DESTINATION_CHANGED;

	/**
	 * A version tracking tag was added
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final VTEvent DOCR_VT_TAG_ADDED = TAG_ADDED;

	/**
	 * A version tracking tag was removed
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final VTEvent DOCR_VT_TAG_REMOVED = TAG_REMOVED;

	/**
	 * The vote count of a match was changed
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final VTEvent DOCR_VT_VOTE_COUNT_CHANGED = VOTE_COUNT_CHANGED;

}
