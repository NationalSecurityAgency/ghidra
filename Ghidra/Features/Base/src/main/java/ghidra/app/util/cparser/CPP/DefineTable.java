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
import ghidra.util.NumericUtilities;

/**
 * 
 */
public class DefineTable {
	// Hastable for storing #defs
	Hashtable<String, PPToken> defs = new Hashtable<String, PPToken>();

	// Hastable for storing #define macro args (substitution list)
	Hashtable<String, Vector<PPToken>> args = new Hashtable<String, Vector<PPToken>>();

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
			Character chObj = new Character(ch);

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
			chObj = new Character(ch);

			Hashtable node = (Hashtable) findTable.get(chObj);

			if (node == null) {
				node = new Hashtable();
				findTable.put(chObj, node);
				findTable = node;
			} else {
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
			chObj = new Character(ch);

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
	 * @return
	 */
	private String macroSub(String image, int pos, ArrayList<String> sublist) {
		int replaceCount = 0;
		
		StringBuffer buf = new StringBuffer(image);
		
		// don't replace an infinite number of times.
		//HashMap<String,Integer> lastReplStrings = new HashMap<String,Integer>();
		while (pos < buf.length() && replaceCount < 900000) {
			String defName = getDefineAt(buf, pos);
			if (shouldReplace(buf,defName,pos)) {
				// stop recursion on the same replacement string
//				if (lastReplStrings.containsKey(defName)) {
//					int lastpos = lastReplStrings.get(defName);
//					Vector<PPToken> argv = getArgs(defName);
//					// if it has no args, don't replace already replaced.
//					if (argv == null && pos < lastpos) {
//						System.out.println("Already did : " + defName);
//						System.out.println("    No repl at " + pos + " lastpos " + lastpos + " : " + buf);
//						pos++;
//						continue;
//					}
//					lastReplStrings.remove(defName);
//				}
				int newpos = replace(buf, defName, pos, sublist);
				// is there a replacement string
				if (newpos == -1) {
					pos++;
				} else {
					//System.err.println(" replace " + defName + " with " + buf.substring(pos,newpos));
					//lastReplStrings.put(defName,pos + defName.length());
					pos = newpos;
					replaceCount++;
				}
			} else {
				pos++;
			}
		}
		if (replaceCount >= 100000) {
			System.err.println(" replace " + image + " hit limit");
		}
		return buf.toString();
	}

	
	private boolean shouldReplace(StringBuffer buf, String defName, int pos) {
		if (defName == null) {
			return false;
		}
		
		//String nextRepl = "";
		int currIndex = buf.indexOf(defName, pos);
		if (currIndex < 0)
			return false; // nothing to replace

		// this match is not exact so skip it (borrowing from JavaCharacter)
		if (currIndex > 0
				&& (Character
						.isJavaIdentifierStart(buf.charAt(currIndex - 1)) || Character
						.isJavaIdentifierPart(buf.charAt(currIndex - 1)))) {
			return false;
		}
		int afterIndex = currIndex + defName.length();
		if (afterIndex < buf.length()
				&& (Character.isJavaIdentifierStart(buf.charAt(afterIndex)) || Character
						.isJavaIdentifierPart(buf.charAt(afterIndex)))) {
			return false;
		}

		//nextRepl = image.substring(0, currIndex);	// shift to location
		String replacementString = defs.get(defName).image;		// get replacement text
		if (replacementString.equals(defName))
			return false; // no need to replace
		
//		// check that macro argv arguments match
//		Vector<PPToken> argv = getArgs(defName);
//		if (argv != null && argv.size() > 0) {
//			// need to scan carefully, and recursively
//			// there shouldn't be so many globals...
//			// could be screwed up by so many things
//			String parms = getParams(buf, currIndex + defName.length(),
//					(char) 0);
//
//			int parmslen = parms.length();
//			if (parmslen < 2) {
//				return false;
//			}
//			parms = parms.trim();
//			if (!parms.startsWith("(") || !parms.endsWith(")")) {
//				return false;
//			}
//		}
			
		return true;
	}

	int replace(StringBuffer buf, String currKey, int fromIndex, ArrayList<String> sublist) {
		String replacementString = null;
		
		if (sublist == null) {
			sublist = new ArrayList<String>();
		}

		//String nextRepl = "";
		int currIndex = buf.indexOf(currKey, fromIndex);
		if (currIndex < 0)
			return -1; // nothing to replace

		// this match is not exact so skip it (borrowing from JavaCharacter)
		if (currIndex > 0
				&& (Character
						.isJavaIdentifierStart(buf.charAt(currIndex - 1)) || Character
						.isJavaIdentifierPart(buf.charAt(currIndex - 1)))) {
			return -1;
		}
		int afterIndex = currIndex + currKey.length();
		if (afterIndex < buf.length()
				&& (Character.isJavaIdentifierStart(buf.charAt(afterIndex)) || Character
						.isJavaIdentifierPart(buf.charAt(afterIndex)))) {
			return -1;
		}

		//nextRepl = image.substring(0, currIndex);	// shift to location
		replacementString = defs.get(currKey).image;		// get replacement text
		if (replacementString.equals(currKey))
			return -1; // no need to replace
		
		// if current def has args, take care of the replacement of them
		Vector<PPToken> argv = getArgs(currKey);
		int replacedSubpieceLen = currKey.length();
		if (argv == null && sublist.contains(currKey)) {
			System.err.println("DONT Replace " + currKey + " in: " + buf);
			return -1;
		}
		if (argv != null && argv.size() > 0) {
			// need to scan carefully, and recursively
			// there shouldn't be so many globals...
			// could be screwed up by so many things
			String parms = getParams(buf, currIndex + currKey.length(),
					(char) 0);

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
		// you may add an else if{} block to warn of malformed macros
			// but the actual culprit may be the Define() non-terminal
		//if (replString != null)
		//	nextRepl += replString;
		
		sublist = new ArrayList<String>(sublist);
		sublist.add(currKey);
		String newReplString = macroSub(replacementString,0, sublist);
		if (newReplString != null) {
			replacementString = newReplString;
		}
		buf.replace(currIndex, currIndex+replacedSubpieceLen, replacementString);
		//nextRepl += image.substring(currIndex + currKey.length());
		return currIndex+replacementString.length();
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
		while (pos < parms.length() || index < argv.size()) {
			String argValue = "";
			if (pos < parms.length()) {
				argValue = getParams(new StringBuffer(parms), pos, ',');
			}
			pos += argValue.length() + 1;
			if (index >= argv.size()) {
				Msg.error(
						this,
						"Define parameter mismatch for macro " + defName
								+ "(" + parms + ")" + " Expected "
								+ argv.size() + " arguments.  "
								+ " badarg(" + index + ") " + argValue
								+ " args processed : " + argsfound);
				return replString;
			}
			String curArgName = argv.elementAt(index).image;
			index++;
			argValue = argValue.trim();
			argsfound.append(argValue);
			argsfound.append(", ");

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
				if (curpos > 0
						&& (Character.isJavaIdentifierStart(substString
								.charAt(curpos - 1)) || Character
								.isJavaIdentifierPart(substString
										.charAt(curpos - 1)))) {
					continue;
				}

				int afterIndex = curpos + curArgName.length();
				if (afterIndex < substString.length()
						&& (Character.isJavaIdentifierStart(substString
								.charAt(afterIndex)) || Character
								.isJavaIdentifierPart(substString
										.charAt(afterIndex)))) {
					continue;
				}

				Integer begin = new Integer(curpos);
				int insertLoc = 0;
				for (; insertLoc < beginPos.size(); insertLoc++) {
					Integer loc = beginPos.get(insertLoc);
					if (loc.compareTo(begin) > 0) {
						break;
					}
				}

				beginPos.add(insertLoc, begin);
				endPos.add(insertLoc,
						new Integer(curpos + curArgName.length()));
				subValue.add(insertLoc, argValue);
			} while (curpos >= 0);
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
		substString = buf.toString();
		return substString;
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
		boolean hitQuote = false;

		while (pos < len) {
			ch = buf.charAt(pos++);
			if (ch == '"') {
				hitQuote = !hitQuote;
			}
			if (!hitQuote && ch == endChar && depth == 0) {
				pos--;
				break;
			}
			if (!hitQuote && ch == ')') {
				depth--;
				if (depth == 0 && endChar == 0)
					break;
				// hit a paren above depth, back up
				if (depth < 0) {
					pos--;
					break;
				}
			}
			if (!hitQuote && ch == '(') {
				depth++;
			}
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
		image = macroSub(image, 0, null);

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
				} while (quotePos > currIndex);

				int afterIndex = currIndex + 2;
				while (currIndex > 0 && image.charAt(currIndex - 1) == ' ') {
					currIndex--; // scan back for first non-blank before ##
				}

				while (afterIndex < image.length()
						&& image.charAt(afterIndex) == ' ') {
					afterIndex++; // scan back for first non-blank before ##
				}

				if (!inString) {
					buf.replace(currIndex, afterIndex, "");
					currIndex--;
				} else {
					currIndex -= 2;
				}
			}
		} while (currIndex > 0);
		image = buf.toString();
		return image;
	}
	
	/**
	 * Given a data type manager, populate defines with constant values as Enums
	 * 
	 */
	
	public void populateDefineEquates(DataTypeManager dtMgr) {
		int transactionID = dtMgr.startTransaction("Add Equates");

		Iterator<String> iter = getDefineNames();
		while (iter.hasNext()) {
			String defName = iter.next();
			// don't worry about macros
			if (isArg(defName)) {
				//System.err.println(defName + " = " + getValue(defName));
				continue;
			}

			// check if this is a numeric expression that could be simplified
			//
			String strValue = getValue(defName);
			String strExpanded = expand(strValue, true);
			strValue = strExpanded;
			
			// strip off any casting/parentheses
			strValue = stripCast(strValue);
			
			long value = 0;
			Long lvalue = getCValue(strValue);

			if (lvalue == null) {
				lvalue = AddressEvaluator.evaluateToLong(strValue);
				if (lvalue == null) {
					continue;
				}
			}

			value = lvalue.longValue();

			String enumName = "define_" + defName;

			EnumDataType enuum = new EnumDataType(enumName, 8);
			enuum.add(defName, value);

			String defPath = getDefinitionPath(defName);
			String currentCategoryName = getFileName(defPath);
			CategoryPath path = getCategory(currentCategoryName);
			path = new CategoryPath(path, "defines");
			enuum.setCategoryPath(path);

			dtMgr.addDataType(enuum, DataTypeConflictHandler.DEFAULT_HANDLER);
		}

		dtMgr.endTransaction(transactionID, true);
	}

	/**
	 * Parse a C format integer value
	 * 
	 * @param strValue value to parse
	 * @return long value if parsable as an integer, null otherwise
	 */
	private static Long getCValue(String strValue) {
		try {
			int start = 0;
			int radix = 10;
			strValue = strValue.toLowerCase();
			if (strValue.startsWith("0x")) {
				start = 2;
				radix = 16;
			} else if (strValue.startsWith("0")) {
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
			int startPos = strValue.indexOf('(',pos);
			if (startPos == -1) {
				return strValue; // done, no more open parens
			}
			pos = startPos;
				int endParen = strValue.indexOf(')', pos+1);
				if (endParen != -1) {
					String subStr = strValue.substring(pos+1, endParen);
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
						   strValue = strValue.substring(0, pos) + strValue.substring(endParen+1);
						   procLen = 0;
					   }
					}
				} else {
					return strValue;  // no more end parens, just finish
				}
			pos = pos + procLen;
		}
		return strValue;
	}

}
