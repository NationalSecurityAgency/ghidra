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

import ghidra.util.Msg;

/**
 * The <CODE>ProgramMergeFilter</CODE> is used to specify which portions of a 
 * program should be merged into another program.
 * It indicates the types of program differences to merge. 
 * Each merge type can have its filter set to <CODE>IGNORE</CODE> or <CODE>REPLACE</CODE>.
 * <CODE>IGNORE</CODE> indicates no interest in replacing or merging that type of difference.
 * <CODE>REPLACE</CODE> indicates to replace differences in program1 with differences of 
 * that type from program2.
 * Some merge types (for example, COMMENTS and SYMBOLS) allow the filter to be 
 * set to <CODE>MERGE</CODE>.
 * <CODE>MERGE</CODE> indicates that the type should
 * be taken from Program2 and merged into Program1 with whatever is alreaady there.
 */
public class ProgramMergeFilter {
	/** Indicates the merge filter difference type specified was not valid. */
	public static final int INVALID = -1;
	/** IGNORE is a <B>filter value</B> indicating that the type of difference isn't to
	 * be changed in the merged program.
	 */
	public static final int IGNORE = 0;
	/** REPLACE is a <B>filter value</B> indicating that the type of difference in program1
	 * should be replaced with the difference from program2.
	 */
	public static final int REPLACE = 1;
	/** MERGE is a <B>filter value</B> indicating that the type of difference should be merged 
	 * from program2 with what is already in program1 (the property type should be taken
	 * from both program1 and program2.)
	 */
	public static final int MERGE = 2;

	////////////////////////////////////////////////////////////////////////
	// The following are definitions for the different types of filtering.
	// Combination filter indicators are created by "OR"ing the individual
	// filter indicators.
	////////////////////////////////////////////////////////////////////////

	/** Internal array index for "program context" filter value. */
	private static final int MERGE_PROGRAM_CONTEXT = 0;
	/** Indicates the <B>merge filter</B> for the program context differences. */
	public static final int PROGRAM_CONTEXT = 1 << MERGE_PROGRAM_CONTEXT;

	/** Internal array index for "bytes" filter value. */
	private static final int MERGE_BYTES = 1;
	/** Indicates the <B>merge filter</B> for the byte differences. */
	public static final int BYTES = 1 << MERGE_BYTES;

	/** Internal array index for "instructions" filter value. */
	private static final int MERGE_INSTRUCTIONS = 2;
	/** Indicates the <B>merge filter</B> for the instruction code unit differences.
	 * This includes mnemonic, operand, and value references, and equates.
	 */
	public static final int INSTRUCTIONS = 1 << MERGE_INSTRUCTIONS;

	/** Internal array index for "data" filter value. */
	private static final int MERGE_DATA = 3;
	/** Indicates the <B>merge filter</B> for the data code unit differences. */
	public static final int DATA = 1 << MERGE_DATA;

	/** Internal array index for "all references" filter value. */
	private static final int MERGE_REFS = 4;
	/** Indicates the <B>merge filter</B> for the memory, variable, and external reference differences. */
	public static final int REFERENCES = 1 << MERGE_REFS;

	/** Internal array index for "plate comments" filter value. */
	private static final int MERGE_PLATE_COMMENTS = 5;
	/** Indicates the <B>merge filter</B> for the plate comment differences. */
	public static final int PLATE_COMMENTS = 1 << MERGE_PLATE_COMMENTS;

	/** Internal array index for "pre comments" filter value. */
	private static final int MERGE_PRE_COMMENTS = 6;
	/** Indicates the <B>merge filter</B> for the pre comment differences. */
	public static final int PRE_COMMENTS = 1 << MERGE_PRE_COMMENTS;

	/** Internal array index for "eol comments" filter value. */
	private static final int MERGE_EOL_COMMENTS = 7;
	/** Indicates the <B>merge filter</B> for the eol comment differences. */
	public static final int EOL_COMMENTS = 1 << MERGE_EOL_COMMENTS;

	/** Internal array index for "repeatable comments" filter value. */
	private static final int MERGE_REPEATABLE_COMMENTS = 8;
	/** Indicates the <B>merge filter</B> for the repeatable comment differences. */
	public static final int REPEATABLE_COMMENTS = 1 << MERGE_REPEATABLE_COMMENTS;

	/** Internal array index for "post comments" filter value. */
	private static final int MERGE_POST_COMMENTS = 9;
	/** Indicates the <B>merge filter</B> for the post comment differences. */
	public static final int POST_COMMENTS = 1 << MERGE_POST_COMMENTS;

	/** Internal array index for "symbols" filter value. */
	private static final int MERGE_SYMBOLS = 10;
	/** Indicates the <B>merge filter</B> for the label differences. */
	public static final int SYMBOLS = 1 << MERGE_SYMBOLS;

	/** Internal array index for "bookmarks" filter value. */
	private static final int MERGE_BOOKMARKS = 11;
	/** Indicates the <B>merge filter</B> for bookmark differences. */
	public static final int BOOKMARKS = 1 << MERGE_BOOKMARKS;

	/** Internal array index for "properties" filter value. */
	private static final int MERGE_PROPERTIES = 12;
	/** Indicates the <B>merge filter</B> for the user defined property differences. */
	public static final int PROPERTIES = 1 << MERGE_PROPERTIES;

	/** Internal array index for "functions" filter value. */
	private static final int MERGE_FUNCTIONS = 13;
	/** Indicates the <B>merge filter</B> for the functions differences. */
	public static final int FUNCTIONS = 1 << MERGE_FUNCTIONS;

	/** Internal array index for "equates" filter value. */
	private static final int MERGE_EQUATES = 14;
	/** Indicates the <B>merge filter</B> for the equates differences. */
	public static final int EQUATES = 1 << MERGE_EQUATES;

	/** Internal array index for "primary symbol" filter value. */
	private static final int MERGE_PRIMARY_SYMBOL = 15;
	/** Indicates the <B>merge filter</B> for replacing the primary symbol with the one from program 2 when merging labels. */
	public static final int PRIMARY_SYMBOL = 1 << MERGE_PRIMARY_SYMBOL;

	/** Internal array index for "function tags" filter value. */
	private static final int MERGE_FUNCTION_TAGS = 16;
	/** Indicates the <B>merge filter</B> for function tags. */
	public static final int FUNCTION_TAGS = 1 << MERGE_FUNCTION_TAGS;

	// NOTE: If you add a new primary type here, make sure to use the
	//       next available integer and update the NUM_PRIMARY_TYPES.
	//       ** Also don't forget to add it to ALL below. **
	/** The total number of primary merge difference types. */
	private static final int NUM_PRIMARY_TYPES = 17;

	/** Indicates to merge code unit differences. This includes instructions,
	 * data, and equates.
	 */
	public static final int CODE_UNITS = INSTRUCTIONS | DATA;

	/** Indicates to merge all comment differences. */
	public static final int COMMENTS = PLATE_COMMENTS | PRE_COMMENTS | EOL_COMMENTS |
		REPEATABLE_COMMENTS | POST_COMMENTS;

	/** Indicates all <B>merge filters</B> for all types of differences. */
	public static final int ALL = PROGRAM_CONTEXT | BYTES | CODE_UNITS | EQUATES | REFERENCES |
		COMMENTS | SYMBOLS | PRIMARY_SYMBOL | BOOKMARKS | PROPERTIES | FUNCTIONS | FUNCTION_TAGS;

	/** Array holding the filter value for each of the primary merge difference types. */
	private int[] filterFlags = new int[NUM_PRIMARY_TYPES];

	/** Creates new ProgramMergeFilter with none of the merge types selected. */
	public ProgramMergeFilter() {
	}

	/** Creates new ProgramMergeFilter that is equal to the specified ProgramMergeFilter. */
	public ProgramMergeFilter(ProgramMergeFilter filter) {
		int length = filter.filterFlags.length;
		this.filterFlags = new int[length];
		System.arraycopy(filter.filterFlags, 0, this.filterFlags, 0, length);
	}

	/** Creates new ProgramMergeFilter with the specified merge types selected.
	 *
	 * @param type the type of difference to look for between the programs.
	 * @param filter IGNORE, REPLACE, or MERGE. Indicates 
	 * which program difference to include of the specified type.
	 * If a particular type cannot be set to MERGE then it will be set to REPLACE.
	 */
	public ProgramMergeFilter(int type, int filter) {
		setFilter(type, filter);
	}

	/** getFilter determines whether or not the specified type of filter is set.
	 * Valid types are: BYTES, INSTRUCTIONS, DATA,
	 * SYMBOLS, PRIMARY_SYMBOL, COMMENTS, PROGRAM_CONTEXT, PROPERTIES, BOOKMARKS, FUNCTIONS.
	 * INVALID is returned if combinations of merge types (e.g. ALL) are 
	 * passed in.
	 *
	 * @param type the merge type.
	 * @return IGNORE, REPLACE, or MERGE. INVALID if parameter is a combination of 
	 * types or not a predefined primary type.
	 */
	public int getFilter(int type) {
		switch (type) {
			case PROGRAM_CONTEXT:
			case BYTES:
			case INSTRUCTIONS:
			case DATA:
			case SYMBOLS:
			case PRIMARY_SYMBOL:
			case REFERENCES:
			case PLATE_COMMENTS:
			case PRE_COMMENTS:
			case EOL_COMMENTS:
			case REPEATABLE_COMMENTS:
			case POST_COMMENTS:
			case BOOKMARKS:
			case PROPERTIES:
			case FUNCTIONS:
			case FUNCTION_TAGS:
			case EQUATES:
				int bitPos = 0;
				int tmpType = type;
				while (bitPos < NUM_PRIMARY_TYPES) {
					if ((tmpType & 1) == 1) { // found the set bit position.
						return filterFlags[bitPos];
					}
					tmpType >>= 1;
					bitPos++;
				}
				return INVALID;
			case CODE_UNITS:
			case COMMENTS:
			case ALL:
			default:
				return INVALID;
		}
	}

	/** validatePredefinedType determines whether or not the indicated type
	 * of filter item is a valid predefined type.
	 * Valid types are: BYTES, INSTRUCTIONS, DATA,
	 * SYMBOLS, PRIMARY_SYMBOL, COMMENTS, PROGRAM_CONTEXT, PROPERTIES, BOOKMARKS, FUNCTIONS, ALL.
	 *
	 * @param type the type of difference to look for between the programs.
	 * @return true if this is a pre-defined merge type.
	 */
	public boolean validatePredefinedType(int type) {
		switch (type) {
			case PROGRAM_CONTEXT:
			case BYTES:
			case INSTRUCTIONS:
			case DATA:
			case SYMBOLS:
			case PRIMARY_SYMBOL:
			case REFERENCES:
			case PLATE_COMMENTS:
			case PRE_COMMENTS:
			case EOL_COMMENTS:
			case REPEATABLE_COMMENTS:
			case POST_COMMENTS:
			case BOOKMARKS:
			case PROPERTIES:
			case FUNCTIONS:
			case FUNCTION_TAGS:
			case EQUATES:
			case CODE_UNITS:
			case COMMENTS:
			case ALL:
				return true;
			default:
				return false;
		}
	}

	/**
	 * Determines if at least one of the filter types is set to REPLACE or MERGE.
	 * @return true if at least one type is set.
	 */
	public boolean isSet() {
		int num = filterFlags.length;
		for (int i = 0; i < num; i++) {
			if (filterFlags[i] != IGNORE) {
				return true;
			}
		}
		return false;
	}

	/** validateType determines whether or not the indicated type of filter item
	 * is valid.
	 * Valid types are: BYTES, INSTRUCTIONS, DATA, REFERENCES,
	 * SYMBOLS, PRIMARY_SYMBOL, COMMENTS, PROGRAM_CONTEXT, PROPERTIES, BOOKMARKS, FUNCTIONS, ALL.
	 * The type can also be any of the predefined types "OR"ed together.
	 *
	 * @param type the type of difference to look for between the programs.
	 * @return true if the type is a valid merge difference type(s).
	 */
	private boolean validateType(int type) {
		if ((type >= 0) && (type < Math.pow(2, (NUM_PRIMARY_TYPES)))) {
			return true;
		}
		return false;
	}

	/** validateFilter determines whether or not the filter is one of our valid
	 *  predefiend values.
	 *  Valid filter values are: IGNORE, REPLACE, or MERGE.
	 *
	 * @param filter the filter value.
	 * @return true if the filter value is valid.
	 */
	private boolean validateFilter(int filter) {
		// Validate the filter.
		if ((filter < IGNORE) || (filter > MERGE)) {
			Msg.error(this, "setFilter: Invalid filter: " + filter);
			return false;
		}
		return true;
	}

	/** isMergeValidForFilter determines whether or not the <CODE>MERGE</CODE>
	 *  filter if valid for the indicated primary merge type.
	 * Possible types are: BYTES, INSTRUCTIONS, DATA, REFERENCES,
	 * SYMBOLS, PRIMARY_SYMBOL, COMMENTS, PROGRAM_CONTEXT, PROPERTIES, BOOKMARKS, FUNCTIONS, ALL.
	 *
	 * @param type the type of difference to merge between the programs.
	 * @return true if <CODE>MERGE</CODE> is valid for the merge type.
	 * @throws IllegalArgumentException if type isn't a predefined individual 
	 * merge type.
	 */
	private boolean isMergeValidForFilter(int type) throws IllegalArgumentException {
		switch (type) {
		// The following can be MERGE.
			case PLATE_COMMENTS:
			case PRE_COMMENTS:
			case EOL_COMMENTS:
			case REPEATABLE_COMMENTS:
			case POST_COMMENTS:
			case SYMBOLS:
			case FUNCTION_TAGS:
				return true;
				// The following cannot be MERGE.
			case PROGRAM_CONTEXT:
			case BYTES:
			case INSTRUCTIONS:
			case DATA:
			case REFERENCES:
			case BOOKMARKS:
			case PROPERTIES:
			case FUNCTIONS:
			case EQUATES:
			case PRIMARY_SYMBOL:
				return false;
			default:
				throw new IllegalArgumentException(
					"Parameter to method isBothFilterValid() must be an individual merge type.");
		}
	}

	/** setFilter specifies whether or not the indicated type of item will
	 * not be included by the filter (IGNORE), replaced in the first program using the type of 
	 * item in the second program (REPLACE), or included from both programs (MERGE).
	 * Valid types are: BYTES, INSTRUCTIONS, DATA, REFERENCES,
	 * SYMBOLS, PRIMARY_SYMBOL, COMMENTS, PROPERTIES, BOOKMARKS, FUNCTIONS, ALL, or combinations of
	 * these "OR"ed together.
	 * if <CODE>MERGE</CODE> is not valid for an included primary type, then it 
	 * will be set to <CODE>REPLACE</CODE> instead for that primary type.
	 *
	 * @param type the type(s) of difference(s) to include.
	 * @param filter IGNORE, REPLACE, or MERGE. Indicates whether to include none, 
	 * one, or both programs' differences of the specified type.
	 */
	synchronized public void setFilter(int type, int filter) {
		// Validate the filter.
		if (!validateType(type)) {
			Msg.error(this, "setFilter: Invalid type.");
			return;
		}
		if (!validateFilter(filter)) {
			Msg.error(this, "setFilter: Invalid filter.");
			return;
		}

		int[] types = getPrimaryTypes();
		for (int i = 0; i < types.length; i++) {
			if ((type & (types[i])) != 0) {
				int tmpFilter = filter;
				if ((filter == MERGE) && (!isMergeValidForFilter(types[i]))) {
					tmpFilter = REPLACE; // Set filter to REPLACE, since MERGE is invalid.
				}
				filterFlags[i] = tmpFilter;
			}
		}
	}

	/**
	 * Returns a printable string indicating the current settings of this filter.
	 * @return the current settings for this filter.
	 */
	@Override
	public String toString() {
		StringBuffer buf = new StringBuffer();
		buf.append("ProgramMergeFilter:\n");
		int[] types = getPrimaryTypes();
		for (int type : types) {
			int filter = this.getFilter(type);
			String s = "  " + typeToName(type) + "=" + filterToName(filter) + "\n";
			buf.append(s);
		}
		return buf.toString();
	}

	/**
	 * Gets all the valid individual types of differences for this filter.
	 * @return an array containing all the currently defined primary difference 
	 * types.
	 */
	public static int[] getPrimaryTypes() {
		int[] pt = new int[NUM_PRIMARY_TYPES];
		for (int i = 0; i < NUM_PRIMARY_TYPES; i++) {
			pt[i] = 1 << i;
		}
		return pt;
	}

	/** <CODE>typeToName()</CODE> returns the name of a predefined merge type.
	 *  Only predefined types, as specified in <CODE>ProgramMergeFilter</CODE>, 
	 *  will return a name. Otherwise, an empty string is returned.
	 * @param type the type of merge difference whose name is wanted.
	 * Valid types are: BYTES, INSTRUCTIONS, DATA, REFERENCES,
	 * SYMBOLS, PRIMARY_SYMBOL, COMMENTS, PROGRAM_CONTEXT, PROPERTIES, BOOKMARKS, FUNCTIONS, ALL.
	 * @return the name of the predefined merge difference type. 
	 * Otherwise, the empty string.
	 */
	public static String typeToName(int type) {
		switch (type) {
			case PROGRAM_CONTEXT:
				return "PROGRAM CONTEXT";
			case BYTES:
				return "BYTES";
			case INSTRUCTIONS:
				return "INSTRUCTIONS";
			case DATA:
				return "DATA";
			case REFERENCES:
				return "REFERENCES";
			case PLATE_COMMENTS:
				return "PLATE_COMMENTS";
			case PRE_COMMENTS:
				return "PRE_COMMENTS";
			case EOL_COMMENTS:
				return "EOL_COMMENTS";
			case REPEATABLE_COMMENTS:
				return "REPEATABLE_COMMENTS";
			case POST_COMMENTS:
				return "POST_COMMENTS";
			case SYMBOLS:
				return "SYMBOLS";
			case PRIMARY_SYMBOL:
				return "PRIMARY_SYMBOL";
			case BOOKMARKS:
				return "BOOKMARKS";
			case PROPERTIES:
				return "PROPERTIES";
			case FUNCTIONS:
				return "FUNCTIONS";
			case FUNCTION_TAGS:
				return "FUNCTION TAGS";
			case EQUATES:
				return "EQUATES";
			case CODE_UNITS:
				return "CODE_UNITS";
			case COMMENTS:
				return "COMMENTS";
			case ALL:
				return "ALL";
			default:
				return "";
		}
	}

	/** <CODE>filterToName</CODE> returns the string associated with an
	 * individual (primary) merge difference setting.
	 * @param type the type of filter.
	 * Valid types are: IGNORE, REPLACE, MERGE.
	 * @return the string indicating the merge difference setting.
	 */
	public static String filterToName(int type) {
		switch (type) {
			case IGNORE:
				return "IGNORE";
			case REPLACE:
				return "REPLACE";
			case MERGE:
				return "MERGE";
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
		if (obj instanceof ProgramMergeFilter) {
			ProgramMergeFilter otherFilter = (ProgramMergeFilter) obj;
			for (int type = 0; type < NUM_PRIMARY_TYPES; type++) {
				if (filterFlags[type] != otherFilter.filterFlags[type]) {
					return false;
				}
			}
			return true;
		}
		return false;
	}

}
