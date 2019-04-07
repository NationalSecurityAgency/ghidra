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
package ghidra.app.merge;

import java.awt.Color;


public interface MergeConstants {
    public static final int RESULT = 0;
    public static final int LATEST = 1;
    public static final int MY = 2;
    public static final int ORIGINAL = 3;
    public static final String RESULT_TITLE = "Result";
    public static final String ORIGINAL_TITLE = "Original";
    public static final String LATEST_TITLE = "Latest";
    public static final String MY_TITLE = "Checked Out"; 
    
    public Color CONFLICT_COLOR = new Color(140, 0, 0);
    public static final Color HIGHLIGHT_COLOR = new Color(230,230,230);
    
    // The following are standardized names for use in passing resolve 
    // information between individual merge managers.
    // For example:
    // the data type merger knows what data type in the result is equivalent 
    // to a given data type from my checked out program. The code unit and
    // function mergers need to be able to get this information so they
    // don't unknowingly re-introduce a data type that was already eliminated
    // by a data type conflict.
    public static final String RESOLVED_LATEST_DTS        = "ResolvedLatestDataTypes";
    public static final String RESOLVED_MY_DTS            = "ResolvedMyDataTypes";
    public static final String RESOLVED_ORIGINAL_DTS      = "ResolvedOriginalDataTypes";
    public static final String RESOLVED_CODE_UNITS        = "ResolvedCodeUnits";
    public static final String PICKED_LATEST_CODE_UNITS   = "PickedLatestCodeUnits";
    public static final String PICKED_MY_CODE_UNITS       = "PickedMyCodeUnits";
    public static final String PICKED_ORIGINAL_CODE_UNITS = "PickedOriginalCodeUnits";
    public static final String RESOLVED_LATEST_SYMBOLS    = "ResolvedLatestSymbols";
    public static final String RESOLVED_MY_SYMBOLS        = "ResolvedMySymbols";
    public static final String RESOLVED_ORIGINAL_SYMBOLS  = "ResolvedOriginalSymbols";
}
