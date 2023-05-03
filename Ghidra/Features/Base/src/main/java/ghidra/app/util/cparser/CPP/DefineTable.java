/* ###
 * IP: GHIDRA
 * NOTE: Generated File!
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
package ghidra.app.util.cparser.CPP;

import java.util.*;

import ghidra.app.util.cparser.CPP.PreProcessor.PPToken;
import ghidra.program.model.data.*;
import ghidra.program.util.AddressEvaluator;
import ghidra.util.Msg;

/**
 * 
 */
public class DefineTable {
	private static final String VARARG_ELLIPSIS = "...";

	// the macro substitution could be done on a very large string, not just
	// a single line, Don't want it to go out of control replacing things
	private static final int ARBITRARY_MAX_REPLACEMENTS = 900000;

	// Hastable for storing #defs
	Hashtable<String, PPToken> defs = new Hashtable<String, PPToken>();

	// Hastable for storing #define macro args (substitution list)
	Hashtable<String, Vector<PPToken>> args = new Hashtable<String, Vector<PPToken>>();

	// Multi-level hashtable with different types of keys and values
	Hashtable lookupTable = new Hashtable();

	private final static String VALUE = "value";

	/**
	 * 
	 */
	public DefineTable() {
		super();
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param string
	 * @return
	 */
	public PPToken get(String string) {
		return defs.get(string);
	}

	/**
	 * @param currKey
	 * @return
	 */
	public Vector<PPToken> getArgs(String currKey) {
		return args.get(currKey);
	}

	/**
	 * @param buf the buffer containing the define
	 * @param pos the position of the define
	 * @return the define
	 */
	public String getDefineAt(StringBuffer buf, int pos) {
		Hashtable findTable = lookupTable;
		String found = null;

		while (findTable != null && pos < buf.length()) {
			char ch = buf.charAt(pos++);
			Character chObj = ch;

			findTable = (Hashtable) findTable.get(chObj);

			// if this node matched a string, remember it
			// we will remember the longest string that matches
			if (findTable != null) {
				String value = (String) findTable.get(VALUE);
				if (value != null) {
					found = value;
				}
			}
		}

		return found;
	}

	/**
	 * Associate a define "name" with a Preprocessor parser token match.
	 * 
	 * @param string - name of define
	 * @param val - token value from parsing
	 */
	public void put(String string, PPToken val) {
		defs.put(string, val);
		Hashtable findTable = lookupTable;
		Character chObj = null;

		int pos = 0;
		int len = string.length();
		while (pos < len) {
			char ch = string.charAt(pos++);
			chObj = ch;

			Hashtable node = (Hashtable) findTable.get(chObj);

			if (node == null) {
				node = new Hashtable();
				findTable.put(chObj, node);
				findTable = node;
			}
			else {
				findTable = node;
			}
		}

		findTable.put(VALUE, string);
	}

	/**
	 * Add an args definition for a define with arguments
	 *     #define bubba(a,b)   (a or b)
	 *     
	 * @param string name of define
	 * @param val set of arg token names
	 */
	public void putArg(String string, Vector<PPToken> val) {
		args.put(string, val);
	}

	/**
	 * See if the define table contains a definition
	 * 
	 * @param def
	 * @return
	 */
	public boolean containsKey(String def) {
		return defs.containsKey(def);
	}

	/**
	 * Size of the define table.
	 * 
	 * @return
	 */
	public int size() {
		return defs.size();
	}

	/**
	 * Remove a definition from the known defines.
	 * 
	 * @param string name of define
	 * @return return the defined token for the named define.
	 */
	public PPToken remove(String string) {
		PPToken token = defs.remove(string);
		Hashtable findTable = lookupTable;
		Character chObj = null;

		int pos = 0;
		int len = string.length();
		while (pos < len) {
			char ch = string.charAt(pos++);
			chObj = Character.valueOf(ch);

			findTable = (Hashtable) findTable.get(chObj);

			if (findTable == null) {
				return token;
			}
		}

		findTable.remove(VALUE);

		return token;
	}

	/**
	 * Check if a define has args.
	 * @param string name of define
	 * @return
	 */
	public boolean isArg(String string) {
		return args.containsKey(string);
	}

	/**
	 * Get rid of args for a define
	 * @param string name of define
	 * @return
	 */
	public Vector<PPToken> removeArg(String string) {
		return args.remove(string);
	}

	/**
	 * display a string for the named define.
	 * @param string named define
	 * @return
	 */
	public String toString(String string) {
		StringBuffer buf = new StringBuffer(string);
		PPToken token = defs.get(string);
		Vector<PPToken> argVector = getArgs(string);

		if (argVector != null) {
			buf.append("(");
			for (int i = 0; i < argVector.size(); i++) {
				PPToken arg = argVector.get(i);
				buf.append(arg);
				if (i + 1 < argVector.size()) {
					buf.append(", ");
				}
			}
			buf.append(" )");
		}
		buf.append(" = " + token.toString());
		return buf.toString();
	}

	/**
	 * @return an iterator over the defined string names
	 */
	public Iterator<String> getDefineNames() {
		return defs.keySet().iterator();
	}

	public String getValue(String defName) {
		PPToken token = defs.get(defName);

		if (token == null) {
			return null;
		}
		return token.image;
	}

	/**
	 * Check if the token that defined this define was numeric
	 * 
	 * @param defName
	 * @return
	 */
	public boolean isNumeric(String defName) {
		PPToken token = defs.get(defName);
		if (token == null) {
			return false;
		}
		return (token.kind == PreProcessorConstants.NUMERIC ||
			token.kind == PreProcessorConstants.FP_NUMERIC);
	}

	public String getDefinitionPath(String defName) {
		PPToken token = defs.get(defName);

		if (token == null) {
			return null;
		}
		return token.getPath();
	}

	/**
	 * return a string with all the macros substitute starting at pos in the input string.
	 * @param image string to expand
	 * @param pos position within string to start expanding
	 * @return string with all substitutions applied
	 */
	private String macroSub(String image, int pos, ArrayList<String> initialList) {
		int replaceCount = 0;

		StringBuffer buf = new StringBuffer(image);
		int lastReplPos = pos;
		
		boolean initialListSupplied = initialList != null;  // initial list passed in
		ArrayList<String> sublist = new ArrayList<String>();
		if (initialList != null) {
			sublist.addAll(initialList);
		}


		// don't replace an infinite number of times.  Fail safe for possible ininite loop
		while (pos < buf.length() && replaceCount < ARBITRARY_MAX_REPLACEMENTS) {
			// clear list of used macros when move past replacement area
			if (pos == lastReplPos) {
				sublist = new ArrayList<String>(); // ok to clear list of used macro names
				if (initialList != null) {
					sublist.addAll(initialList); // add back in initialList of nonreplacement names
				}
			}
			String defName = getDefineAt(buf, pos);
			if (shouldReplace(buf, defName, pos)) {
				// stop recursion on the same replacement string
				int replPos = replace(buf, defName, pos, sublist, initialListSupplied);

				if (replPos == -1) {
					// if no replacement string, move on
					pos++;
				}
				else {
					// replaced text, update the last place a replacement was made
					lastReplPos = replPos;
					replaceCount++;
				}
			}
			else {
				pos++;
			}
		}
		if (replaceCount >= ARBITRARY_MAX_REPLACEMENTS) {
			System.err.println(" replace " + image + " hit limit");
		}
		return buf.toString();
	}

	private boolean shouldReplace(StringBuffer buf, String defName, int pos) {
		if (defName == null) {
			return false;
		}

		int currIndex = buf.indexOf(defName, pos);
		if (currIndex < 0) {
			return false; // nothing to replace
		}

		// this match is not exact so skip it (borrowing from JavaCharacter)
		if (currIndex > 0 && (Character.isJavaIdentifierStart(buf.charAt(currIndex - 1)) ||
			Character.isJavaIdentifierPart(buf.charAt(currIndex - 1)))) {
			return false;
		}
		int afterIndex = currIndex + defName.length();
		if (afterIndex < buf.length() && (Character.isJavaIdentifierStart(buf.charAt(afterIndex)) ||
			Character.isJavaIdentifierPart(buf.charAt(afterIndex)))) {
			return false;
		}

		//nextRepl = image.substring(0, currIndex);	// shift to location
		String replacementString = defs.get(defName).image;		// get replacement text
		if (replacementString.equals(defName)) {
			return false; // no need to replace
		}

		return true;
	}

	int replace(StringBuffer buf, String currKey, int fromIndex, ArrayList<String> sublist, boolean initialList) {
		String replacementString = null;

		if (sublist == null) {
			sublist = new ArrayList<String>();
		}

		//String nextRepl = "";
		int currIndex = buf.indexOf(currKey, fromIndex);
		if (currIndex < 0) {
			return -1; // nothing to replace
		}

		// this match is not exact so skip it (borrowing from JavaCharacter)
		if (currIndex > 0 && (Character.isJavaIdentifierStart(buf.charAt(currIndex - 1)) ||
			Character.isJavaIdentifierPart(buf.charAt(currIndex - 1)))) {
			return -1;
		}
		int afterIndex = currIndex + currKey.length();
		if (afterIndex < buf.length() && (Character.isJavaIdentifierStart(buf.charAt(afterIndex)) ||
			Character.isJavaIdentifierPart(buf.charAt(afterIndex)))) {
			return -1;
		}

		//nextRepl = image.substring(0, currIndex);	// shift to location
		replacementString = defs.get(currKey).image;		// get replacement text
		if (replacementString.equals(currKey)) {
			return -1; // no need to replace
		}

		// if current def has args, take care of the replacement of them
		Vector<PPToken> argv = getArgs(currKey);
		int replacedSubpieceLen = currKey.length();
		if (argv == null && sublist.contains(currKey)) {
			if (!initialList) {
				System.err.println("DONT Replace " + currKey + " in: " + buf);
			}
			return -1;
		}
		if (argv != null) {
			// need to scan carefully, and recursively
			// there shouldn't be so many globals...
			// could be screwed up by so many things
			String parms = getParams(buf, currIndex + currKey.length(), (char) 0);

			int parmslen = parms.length();
			if (parmslen < 2) {
				return -1;
			}
			parms = parms.trim();
			if (!parms.startsWith("(") || !parms.endsWith(")")) {
				return -1;
			}

			parms = parms.substring(1, parms.length() - 1);
			replacementString = subParams(replacementString, currKey, parms, argv);

			replacementString = joinPdPd(replacementString);

			replacedSubpieceLen += parmslen;
		}

		sublist.add(currKey);
		buf.replace(currIndex, currIndex + replacedSubpieceLen, replacementString);
		return currIndex + replacementString.length();
	}

	/**
	 * expand a define with arguments
	 * 
	 * @return the newly expanded string
	 */
	String subParams(String replString, String defName, String parms, Vector<PPToken> argv) {
		String substString = replString;

		ArrayList<Integer> beginPos = new ArrayList<Integer>();
		ArrayList<Integer> endPos = new ArrayList<Integer>();
		ArrayList<String> subValue = new ArrayList<>();
		int index = 0;
		int pos = 0;
		StringBuffer argsfound = new StringBuffer();
		boolean isVarArg = false;
		boolean hadVarArgs = false;
		while (pos < parms.length() || index < argv.size()) {
			String argValue = "";
			int origPos = pos;
			if (pos < parms.length()) {
				argValue = getParams(new StringBuffer(parms), pos, ',');
			}
			pos += argValue.length() + 1;

			if (index >= argv.size()) {
				Msg.error(this,
					"Define parameter mismatch for macro " + defName + "(" + parms + ")" +
						" Expected " + argv.size() + " arguments.  " + " badarg(" + index + ") " +
						argValue + " args processed : " + argsfound);
				return replString;
			}
			
			// Handle "..." varargs
			//    if last argument is ellipsis, then is varargs, replace the rest of the params
			String curArgName = argv.elementAt(index).image;
			if (index == argv.size()-1 && VARARG_ELLIPSIS.equals(curArgName)) {
				isVarArg = true;
				//   Replace __VA_ARGS__ with the rest of params
				curArgName = "__VA_ARGS__";
				argValue = getParams(new StringBuffer(parms), origPos, '\0');
				pos += argValue.length() + 1;
			}
			index++;
			argValue = argValue.trim();
			argsfound.append(argValue);
			argsfound.append(", ");

			// isVarArg, and had variable arguments
			if (isVarArg && argValue.length() != 0) {
				hadVarArgs = true;
			}

			int curpos = -1;
			// find argname in substString
			// note begin and end position
			do {
				curpos = substString.indexOf(curArgName, curpos + 1);

				if (curpos < 0) {
					continue;
				}

				// this match is not exact so skip it (borrowing from
				// JavaCharacter)
				if (curpos > 0 &&
					(Character.isJavaIdentifierStart(substString.charAt(curpos - 1)) ||
						Character.isJavaIdentifierPart(substString.charAt(curpos - 1)))) {
					continue;
				}

				int afterIndex = curpos + curArgName.length();
				if (afterIndex < substString.length() &&
					(Character.isJavaIdentifierStart(substString.charAt(afterIndex)) ||
						Character.isJavaIdentifierPart(substString.charAt(afterIndex)))) {
					continue;
				}

				Integer begin = Integer.valueOf(curpos);
				int insertLoc = 0;
				for (; insertLoc < beginPos.size(); insertLoc++) {
					Integer loc = beginPos.get(insertLoc);
					if (loc.compareTo(begin) > 0) {
						break;
					}
				}

				beginPos.add(insertLoc, begin);
				endPos.add(insertLoc, Integer.valueOf(curpos + curArgName.length()));
				subValue.add(insertLoc, argValue);
			}
			while (curpos >= 0);
		}

		StringBuffer buf = new StringBuffer();
		int listSize = beginPos.size();
		int startpos = 0;
		for (int i = 0; i < listSize; i++) {
			int begin = beginPos.get(i).intValue();
			int end = endPos.get(i).intValue();
			String value = subValue.get(i);

			buf.append(substString.substring(startpos, begin));
			buf.append(value);
			startpos = end;
		}
		buf.append(substString.substring(startpos));
		
		// Handle __VA_OPT__(<repl>)
		//    if varargs and no more params, replace with ""
		//    if varargs and has vararg params, replace with <repl>
		if (isVarArg) {
			replace_VaOpt(buf, hadVarArgs);
		}
		
		substString = buf.toString();
		return substString;
	}

	/**
	 * Replace __VA_OPT__(arg) in buf with either the arg to __VA_OPT__
	 * if there were any VARARGS, otherwise with ""
	 * @param buf string buffer to replace __VA_OPT__(value) within
	 * @param hadVarArgs
	 */
	private void replace_VaOpt(StringBuffer buf, boolean hadVarArgs) {		
		int optIdx = buf.indexOf("__VA_OPT__");
		if (optIdx < 0) {
			return;
		}
		
		int lparen = buf.indexOf("(", optIdx+1);
		if (lparen < 0) {
			return;
		}
		
		int rparen = buf.indexOf(")",lparen+1);
		if (rparen < 0) {
			return;
		}
		
		// get in between string.
		String replarg = buf.substring(lparen+1, rparen);
		if (hadVarArgs) {
			buf.replace(optIdx, rparen+1, replarg);
		} else {
			buf.replace(optIdx, rparen+1, "");
		}
	}

	/**
	 * @param buf the buffer containing the parameters
	 * @param start the starting index of the parameters in the buffer
	 * @param endChar the delimiter for the parameters
	 * @return the parameters
	 */
	public String getParams(StringBuffer buf, int start, char endChar) {
		int len = buf.length();
		int depth = 0;
		int pos = start;
		if (pos >= len) {
			return "";
		}

		char ch = buf.charAt(pos);
		char lastChar = 0;
		boolean hitQuote = false;
		boolean hitTick = false;

		while (pos < len) {
			ch = buf.charAt(pos++);
			if (ch == '"' && lastChar != '\\') {
				hitQuote = !hitQuote;
			}
			if (ch == '\'' && lastChar != '\\') {
				hitTick = !hitTick;
			}
			if (!(hitQuote || hitTick) && ch == endChar && depth == 0) {
				pos--;
				break;
			}
			if (!(hitQuote || hitTick) && ch == ')') {
				depth--;
				if (depth == 0 && endChar == 0) {
					break;
				}
				// hit a paren above depth, back up
				if (depth < 0) {
					pos--;
					break;
				}
			}
			if (!(hitQuote || hitTick) && ch == '(') {
				depth++;
			}
			lastChar = ch;
		}
		return buf.substring(start, pos);
	}

	/**
	 * do the final expansion of "##" concats in the define strings that protect normal macro substitution.
	 * 
	 * @param image
	 * @param join
	 * @return
	 */
	public String expand(String image, boolean join) {
		return expand(image, join, null);
	}
	
	/**
	 * do the final expansion of "##" concats in the define strings that protect normal macro substitution.
	 * 
	 * @param image
	 * @param join
	 * @param list of defines not to re-replace, stops recursive replacement on a define
	 * @return
	 */
	public String expand(String image, boolean join, ArrayList<String> list) {
		
		image = macroSub(image, 0, list);

		// get rid of ## constructs
		if (join) {
			image = joinPdPd(image);
		}
		if (image.length() > 0 && image.charAt(0) == '#') {
			image = "\"" + image.substring(1) + "\"";
		}

		return image;
	}

	private String joinPdPd(String image) {
		int currIndex = image.length();
		StringBuffer buf = new StringBuffer(image);
		do {
			currIndex = image.lastIndexOf("##", currIndex);
			if (currIndex >= 0) {
				// TODO: must check that it isn't inside of a string
				boolean inString = false;
				int quotePos = image.length();
				do {
					quotePos = image.lastIndexOf("\"", quotePos);
					if (quotePos > currIndex && quotePos >= 0) {
						inString = !inString;
					}
					quotePos--;
				}
				while (quotePos > currIndex);

				int afterIndex = currIndex + 2;
				while (currIndex > 0 && image.charAt(currIndex - 1) == ' ') {
					currIndex--; // scan back for first non-blank before ##
				}

				while (afterIndex < image.length() && image.charAt(afterIndex) == ' ') {
					afterIndex++; // scan back for first non-blank before ##
				}

				if (!inString) {
					buf.replace(currIndex, afterIndex, "");
					currIndex--;
				}
				else {
					currIndex -= 2;
				}
			}
		}
		while (currIndex > 0);
		image = buf.toString();
		return image;
	}

	/**
	 * Given a data type manager, populate defines with constant values as Enums
	 * 
	 */

	public void populateDefineEquates(DataTypeManager openDTMgrs[], DataTypeManager dtMgr) {
		int transactionID = dtMgr.startTransaction("Add Equates");

		Iterator<String> iter = getDefineNames();
		while (iter.hasNext()) {
			String defName = iter.next();
			
			String strValue = expandDefine(defName);
			if (strValue == null) {
				// couldn't expand, must have been a macro
				continue;
			}
			
			// strip off any casting/parentheses
			strValue = stripCast(strValue);

			long value = 0;
			Long lvalue = getCValue(strValue);

			if (lvalue == null) {
				try {
					lvalue = AddressEvaluator.evaluateToLong(strValue);
				}
				catch (Exception exc) {
					// ignore didn't parse well
				}
				if (lvalue == null) {
					continue;
				}
			}

			value = lvalue.longValue();

			populateDefineEquate(openDTMgrs, dtMgr, "defines", "define_", defName, value);
		}

		dtMgr.endTransaction(transactionID, true);
	}

	public void populateDefineEquate(DataTypeManager openDTMgrs[], DataTypeManager dtMgr, String category, String prefix, String defName, long value) {
		String enumName = prefix + defName;

		// Start the Enum at 8, then resize to fit the value
		EnumDataType enuum = new EnumDataType(enumName, 8);
		enuum.add(defName, value);
		enuum.setLength(enuum.getMinimumPossibleLength());

		String defPath = getDefinitionPath(defName);
		String currentCategoryName = getFileName(defPath);
		CategoryPath path = getCategory(currentCategoryName);
		path = new CategoryPath(path, category);
		enuum.setCategoryPath(path);
		
		DataType dt = resolveDataType(openDTMgrs, path, enuum);

		dtMgr.addDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
	}
	
    private DataType resolveDataType(DataTypeManager openDTMgrs[], CategoryPath path, DataType dt) {
    	if (openDTMgrs == null) {
    		return dt;
    	}
        // If the exact data type exists in any open DTMgr, use the open DTmgr type
        // instead

        for (int i = 0; i < openDTMgrs.length; i++) {
            // look for the data type by name
            //    equivalent, return it
            // look for the data type by category
            //    equivalent, return it
        	DataType candidateDT = openDTMgrs[i].getDataType(dt.getCategoryPath(), dt.getName());
        	
        	if (candidateDT != null && candidateDT.isEquivalent(candidateDT)) {
        		return candidateDT;
        	}
        }

        return dt;
    }

	public String expandDefine(String defName) {
		// don't worry about macros
		if (isArg(defName)) {
			//System.err.println(defName + " = " + getValue(defName));
			return null;
		}

		// check if this is a numeric expression that could be simplified
		//
		String strValue = getValue(defName);
		
		ArrayList<String> list = new ArrayList();
		list.add(defName);
		
		String strExpanded = expand(strValue, true, list);
		strValue = strExpanded;
		
		return strValue;
	}

	/**
	 * Parse a C format integer value
	 * 
	 * @param strValue value to parse
	 * @return long value if parsable as an integer, null otherwise
	 */
	public static Long getCValue(String strValue) {
		try {
			int start = 0;
			int radix = 10;
			strValue = strValue.toLowerCase();
			if (strValue.startsWith("0x")) {
				start = 2;
				radix = 16;
			}
			else if (strValue.startsWith("0")) {
				start = 1;
				radix = 8;
			}
			if (strValue.endsWith("ul") || strValue.endsWith("ll")) {
				strValue = strValue.substring(0, strValue.length() - 2);
			}
			else if (strValue.endsWith("l") || strValue.endsWith("u")) {
				strValue = strValue.substring(0, strValue.length() - 1);
			}

			if (start != 0) {
				strValue = strValue.substring(start);
			}

			return Long.parseLong(strValue, radix);
		}
		catch (RuntimeException e) {
			// something went wrong, just return null
		}
		return null;
	}

	/*
	 * create a category path based on a name, or the root category with no name
	 */
	private static CategoryPath getCategory(String catName) {
		CategoryPath rootCat = CategoryPath.ROOT;
		if (catName == null || catName.length() == 0) {
			return rootCat;
		}
		return new CategoryPath(rootCat, catName);
	}

	/*
	 * Get the filename portion of a path
	 */
	private static String getFileName(String path) {
		if (path == null) {
			return null;
		}
		int slashpos = path.lastIndexOf('/');
		if (slashpos < 0) {
			slashpos = path.lastIndexOf('\\');
		}
		if (slashpos < 0) {
			return path;
		}
		return path.substring(slashpos + 1);
	}

	/*
	 * Strip off any casts
	 */
	private static String stripCast(String strValue) {
		strValue = strValue.trim();

		int pos = 0;
		while (pos < strValue.length()) {
			int procLen = 1;
			int startPos = strValue.indexOf('(', pos);
			if (startPos == -1) {
				return strValue; // done, no more open parens
			}
			pos = startPos;
			int endParen = strValue.indexOf(')', pos + 1);
			if (endParen != -1) {
				String subStr = strValue.substring(pos + 1, endParen);
				if (subStr.length() > 0) {
					int subPos = 0;
					subStr = subStr.trim();
					boolean isValid = Character.isJavaIdentifierStart(subStr.charAt(0));
					while (isValid && subPos < subStr.length()) {
						char ch = subStr.charAt(subPos++);
						isValid |= Character.isJavaIdentifierPart(ch);
					}
					// if looks like a cast, throw it away
					if (isValid) {
						strValue = strValue.substring(0, pos) + strValue.substring(endParen + 1);
						procLen = 0;
					}
				}
			}
			else {
				return strValue;  // no more end parens, just finish
			}
			pos = pos + procLen;
		}
		return strValue;
	}

}
