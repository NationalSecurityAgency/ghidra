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
package ghidra.app.merge.listing;

import ghidra.app.merge.MergeConstants;

/**
 * <code>ListingMergeConstants</code> is an interface that provides constants 
 * that are used throughout all of the Listing merge managers for multi-user.
 */
public interface ListingMergeConstants {

	/** Conflict Option indicating the user canceled the merge. */
	public static final int CANCELED = -1;
	/** Conflict Option indicating to prompt the user for a response. */
	public static final int ASK_USER = 0;
	/** Indicates a row on the conflicts panel is strictly information and doesn't contain a choice. */
	public static final int INFO_ROW = 0;
	/** Keep the Original program's information to resolve a conflict. */
	public static final int KEEP_ORIGINAL = 1;
	/** Keep the Latest program's information to resolve a conflict. */
	public static final int KEEP_LATEST = 2;
	/** Keep My program's information to resolve a conflict. */
	public static final int KEEP_MY = 4;
	/** Keep Result program's existing information to resolve a conflict. */
	public static final int KEEP_RESULT = 8;
	/** Keep both the Latest program's and My program's information to resolve a conflict. */
	public static final int KEEP_BOTH = KEEP_LATEST | KEEP_MY; // LATEST & MY
	/** Keep the Original program's, the Latest program's, and My program's information to resolve a conflict. */
	public static final int KEEP_ALL = KEEP_LATEST | KEEP_MY | KEEP_ORIGINAL; // LATEST & MY & ORIGINAL
	/** Remove the Latest program's conflict item to resolve a conflict. */
	public static final int REMOVE_LATEST = 8;
	/** Rename the conflict item as in the Latest program to resolve a conflict. */
	public static final int RENAME_LATEST = 16;
	/** Remove the My program's conflict item to resolve a conflict. */
	public static final int REMOVE_MY = 32;
	/** Rename the conflict item as in My program to resolve a conflict. */
	public static final int RENAME_MY = 64;

	/** Maximum length to display before truncating occurs in conflict panel.
	 * This is needed for comments, etc. which could be very large.
	 */
	public static final int TRUNCATE_LENGTH = 160;

	// Standaradized strings for refering to each of the versioned programs.
	public static final String RESULT_TITLE = MergeConstants.RESULT_TITLE;
	public static final String ORIGINAL_TITLE = MergeConstants.ORIGINAL_TITLE;
	public static final String LATEST_TITLE = MergeConstants.LATEST_TITLE;
	public static final String MY_TITLE = MergeConstants.MY_TITLE;

	// The following are names necessary for referencing GUI components.
	public static final String LATEST_LIST_BUTTON_NAME = "LatestListRB";
	public static final String CHECKED_OUT_LIST_BUTTON_NAME = "CheckedOutListRB";
	public static final String LATEST_BUTTON_NAME = "LatestVersionRB";
	public static final String CHECKED_OUT_BUTTON_NAME = "CheckedOutVersionRB";
	public static final String ORIGINAL_BUTTON_NAME = "OriginalVersionRB";
	public static final String RESULT_BUTTON_NAME = "ResultVersionRB";
	public static final String LATEST_CHECK_BOX_NAME = "LatestVersionCheckBox";
	public static final String CHECKED_OUT_CHECK_BOX_NAME = "CheckedOutVersionCheckBox";
	public static final String ORIGINAL_CHECK_BOX_NAME = "OriginalVersionCheckBox";
	public static final String LATEST_LABEL_NAME = "LatestVersionLabel";
	public static final String CHECKED_OUT_LABEL_NAME = "CheckedOutVersionLabel";
	public static final String ORIGINAL_LABEL_NAME = "OriginalVersionLabel";
	public static final String REMOVE_LATEST_BUTTON_NAME = "RemoveLatestRB";
	public static final String RENAME_LATEST_BUTTON_NAME = "RenameLatestRB";
	public static final String REMOVE_CHECKED_OUT_BUTTON_NAME = "RemoveCheckedOutRB";
	public static final String RENAME_CHECKED_OUT_BUTTON_NAME = "RenameCheckedOutRB";

}
