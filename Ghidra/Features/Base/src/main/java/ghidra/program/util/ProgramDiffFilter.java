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
package ghidra.program.util;

/**
 * The <CODE>ProgramDiffFilter</CODE> is used when determining or working with
 * differences between two programs.
 * It indicates the types of program differences we are interested in.
 * Each difference type can be set to true, indicating interest in
 * differences of that type between two programs. False indicates no interest
 * in this type of program difference.
 * <BR>Valid filter types are: 
 * BYTE_DIFFS, CODE_UNIT_DIFFS, 
 * PLATE_COMMENT_DIFFS, PRE_COMMENT_DIFFS, EOL_COMMENT_DIFFS, 
 * REPEATABLE_COMMENT_DIFFS, POST_COMMENT_DIFFS,
 * REFERENCE_DIFFS,
 * USER_DEFINED_DIFFS, BOOKMARK_DIFFS,
 * SYMBOL_DIFFS,
 * EQUATE_DIFFS, FUNCTION_DIFFS, PROGRAM_CONTEXT_DIFFS.
 * <BR>Predefined filter type combinations are:
 * COMMENT_DIFFS and ALL_DIFFS.
 */
public class ProgramDiffFilter {

    ////////////////////////////////////////////////////////////////////////
    // The following are definitions for the different types of filtering.
    // Combination filter indicators are created by "OR"ing the individual
    // filter indicators.
    ////////////////////////////////////////////////////////////////////////
	/** Indicates the filter for the program context (register) differences. */
	public static final int PROGRAM_CONTEXT_DIFFS = 1 << 0;
    /** Indicates the filter for the byte differences. */
    public static final int BYTE_DIFFS = 1 << 1;
    /** Indicates the filter for the code unit differences. */
    public static final int CODE_UNIT_DIFFS = 1 << 2;
	/** Indicates the filter for the end of line comment differences. */
	public static final int EOL_COMMENT_DIFFS = 1 << 3;
	/** Indicates the filter for the pre comment differences. */
	public static final int PRE_COMMENT_DIFFS = 1 << 4;
	/** Indicates the filter for the post comment differences. */
	public static final int POST_COMMENT_DIFFS = 1 << 5;
	/** Indicates the filter for the plate comment differences. */
	public static final int PLATE_COMMENT_DIFFS = 1 << 6;
	/** Indicates the filter for the repeatable comment differences. */
	public static final int REPEATABLE_COMMENT_DIFFS = 1 << 7;
	/** Indicates the filter for memory, variable, and external reference differences. */
	public static final int REFERENCE_DIFFS = 1 << 8;
	/** Indicates the filter for the equates differences. */
	public static final int EQUATE_DIFFS = 1 << 9;
    /** Indicates the filter for the symbol differences. */
    public static final int SYMBOL_DIFFS = 1 << 10;
	/** Indicates the filter for the function differences. */
	public static final int FUNCTION_DIFFS = 1 << 11;
	/** Indicates the filter for bookmark differences. */
	public static final int BOOKMARK_DIFFS = 1 << 12;
	/** Indicates the filter for the user defined property differences. */
	public static final int USER_DEFINED_DIFFS = 1 << 13;
	/** Indicates the filter for the function tag differences. */
	public static final int FUNCTION_TAG_DIFFS = 1 << 14;
    
    // NOTE: If you add a new primary type here, make sure to use the
    //       next available bit position and update the NUM_PRIMARY_TYPES.
    //       ** Also don't forget to add it to ALL_DIFFS below. **
    /** The total number of primary difference types. */
	private static final int NUM_PRIMARY_TYPES = 15;

    //********************************************************
    //* PREDEFINED DIFFERENCE COMBINATIONS
    //********************************************************
	/** Indicates all comment filters. */
	public static final int COMMENT_DIFFS = 
										EOL_COMMENT_DIFFS
									  | PRE_COMMENT_DIFFS
									  | POST_COMMENT_DIFFS
									  | REPEATABLE_COMMENT_DIFFS
									  | PLATE_COMMENT_DIFFS;
	/** Indicates all filters for all defined types of differences. */
	//@formatter:off
	public static final int ALL_DIFFS = 
										BYTE_DIFFS
									  | CODE_UNIT_DIFFS
									  | COMMENT_DIFFS
									  | REFERENCE_DIFFS
									  | USER_DEFINED_DIFFS
									  | SYMBOL_DIFFS
									  | EQUATE_DIFFS
									  | FUNCTION_DIFFS
									  | BOOKMARK_DIFFS
									  | FUNCTION_TAG_DIFFS 
									  | PROGRAM_CONTEXT_DIFFS;
	//@formatter:on

    /** <CODE>filterFlags</CODE> holds the actual indicators for each
     *  difference type as a bit setting.
     */
    private int filterFlags = 0;


    /** Creates new ProgramDiffFilter with none of the diff types selected.*/
    public ProgramDiffFilter() {
    }

	/** Creates new ProgramDiffFilter equivalent to the specified ProgramDiffFilter.
	 *
	 * @param filter the diff filter this one should equal.
	 */
	public ProgramDiffFilter(ProgramDiffFilter filter) {
		this.filterFlags = filter.filterFlags;
	}

    /** Creates new ProgramDiffFilter with the specified diff types selected.
     *
     * @param type one or more of the diff types "OR"ed together.
     * <BR>i.e. CODE_UNIT_DIFFS | SYMBOL_DIFFS
     */
    public ProgramDiffFilter(int type) {
        filterFlags = ALL_DIFFS & type;
    }

    /**
     * getFilter determines whether or not the specified type of filter is set.
     *
     * @param type the set bits indicate the type of differences we want to 
     * check as being set in the filter.
     * <BR>For example, one or more of the diff types "OR"ed together.
     * <BR>i.e. CODE_UNIT_DIFFS | SYMBOL_DIFFS
     * @return true if filtering for the specified type of differences.
     */
    public boolean getFilter(int type) {
        return ((type & filterFlags) != 0);
    }

    /** set this filter to look for types of differences in addition to those
     * types where it is already looking for differences.
     * The filter that is passed as a parameter indicates the additional types
     * of differences.
     *
     * @param filter filter indicating the additional types of differences
     * to look for between the programs.
     */
    synchronized public void addToFilter(ProgramDiffFilter filter) {
        filterFlags |= filter.filterFlags;
    }

	/** setFilter specifies whether or not the indicated type of difference will be
	 * included by the filter (true) or not included (false).
	 *
     * @param type the set bits indicate the type of differences we want to 
     * look for in the programs.
     * <BR>For example, one or more of the diff types "OR"ed together.
     * <BR>i.e. CODE_UNIT_DIFFS | SYMBOL_DIFFS
	 * @param filter true if you want to determine differences of the specified type.
	 */
	synchronized public void setFilter(int type, boolean filter) {
		if (filter) {
			filterFlags |= type;
		}
		else {
			filterFlags &= (~type);
		}
	}

    /**
     * Sets all the defined types of differences to false.
     * Filter indicates no interest in any difference types.
     */
    public void clearAll() {
        setFilter(ALL_DIFFS, false);
    }

    /**
     * Sets all the defined types of differences to true.
     * Filter indicates interest in all difference types.
     */
    public void selectAll() {
        setFilter(ALL_DIFFS, true);
    }

    /**
     * Gets all the valid individual types of differences for this filter.
     * These are also referred to as primary difference types.
     * @return an array containing all the currently defined difference types
     */
    public static int[] getPrimaryTypes() {
        int[] pt = new int[NUM_PRIMARY_TYPES];
        for (int i=0; i<NUM_PRIMARY_TYPES; i++) {
            pt[i] = 1 << i;
        }
        return pt;
    }

    /** <CODE>typeToName()</CODE> returns the name of the difference type.
     *  Only predefined types, as specified in <CODE>ProgramDiffFilter</CODE>,
     *  will return a name. Otherwise, an empty string is returned.
     * @param type the type of difference whose name is wanted.
     * @return the name of the predefined difference type. Otherwise, the empty string.
     */
    public static String typeToName(int type) {
        switch (type) {
             case ProgramDiffFilter.BYTE_DIFFS:
                return "BYTE_DIFFS";
            case ProgramDiffFilter.CODE_UNIT_DIFFS:
                return "CODE_UNIT_DIFFS";
			case ProgramDiffFilter.COMMENT_DIFFS:
				return "COMMENT_DIFFS";
			case ProgramDiffFilter.EOL_COMMENT_DIFFS:
				return "EOL_COMMENT_DIFFS";
			case ProgramDiffFilter.PRE_COMMENT_DIFFS:
				return "PRE_COMMENT_DIFFS";
			case ProgramDiffFilter.POST_COMMENT_DIFFS:
				return "POST_COMMENT_DIFFS";
			case ProgramDiffFilter.PLATE_COMMENT_DIFFS:
				return "PLATE_COMMENT_DIFFS";
			case ProgramDiffFilter.REPEATABLE_COMMENT_DIFFS:
				return "REPEATABLE_COMMENT_DIFFS";
            case ProgramDiffFilter.REFERENCE_DIFFS:
                return "REFERENCE_DIFFS";
            case ProgramDiffFilter.USER_DEFINED_DIFFS:
                return "USER_DEFINED_DIFFS";
			case ProgramDiffFilter.SYMBOL_DIFFS:
				return "SYMBOL_DIFFS";
            case ProgramDiffFilter.EQUATE_DIFFS:
                return "EQUATE_DIFFS";
			case ProgramDiffFilter.FUNCTION_DIFFS:
				return "FUNCTION_DIFFS";
			case ProgramDiffFilter.BOOKMARK_DIFFS:
				return "BOOKMARK_DIFFS";
            case ProgramDiffFilter.PROGRAM_CONTEXT_DIFFS:
                return "PROGRAM_CONTEXT_DIFFS";
            case ProgramDiffFilter.ALL_DIFFS:
                return "ALL_DIFFS";
			case ProgramDiffFilter.FUNCTION_TAG_DIFFS:
				return "FUNCTION_TAG_DIFFS";
            default:
                return "";
        }
    }

    /**
     * Determines whether or not this filter is equal to the object that
     * is passed in.
     * @param obj the object to compare this one with.
     * @return true if the filter matches this one.
     */
    @Override
    public boolean equals(Object obj) {
        if (obj instanceof ProgramDiffFilter) {
            return ((ProgramDiffFilter)obj).filterFlags == filterFlags;
        }
        return false;
    }
    
    /**
     * Returns a string representation of the current settings for this filter.
     */
    @Override
    public String toString() {
    	StringBuffer buf = new StringBuffer();
    	buf.append("ProgramDiffFilter:\n");
    	for (int i=0; i<NUM_PRIMARY_TYPES; i++) {
    		buf.append("  "+typeToName(1<<i)+"="+getFilter(1<<i)+"\n");
    	}
    	return buf.toString();
    }
}
