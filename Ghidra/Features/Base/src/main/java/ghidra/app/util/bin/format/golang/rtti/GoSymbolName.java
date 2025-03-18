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
package ghidra.app.util.bin.format.golang.rtti;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Represents a Golang symbol name.
 * <p>
 * Handles formats such as:
 * <p>
 * "package/domain.name/packagename.(*ReceiverTypeName).Functionname"
 * or
 * "package/domain.name/packagename.(*ReceiverTypeName[genericinfo { method(); fieldname fieldtype; }]).Functionname"
 * or
 * "package/domain.name/packagename.Functionname[genericinfo]"
 * or
 * "type:.eq.[39]package/domain.name/packagename.Functionname"
 * 
 * @param symbolName full name of the golang symbol
 * @param packagePath portion the symbol name that is the packagePath (path+packagename), or null
 * @param packageName portion of the symbol name that is the package name, or null
 * @param receiverString portion of the symbol name that is the receiver string (only found when
 * the receiver is in the form of "(*typename)"), or null
 * @param genericInfo portion of the symbol name found inside of a generics "[blah]"
 * @param baseName symbol base name
 * @param prefix portion of the symbol name that was prepended to the main symbol info
 * @param symtype {@link GoSymbolNameType} enum specifying what kind of object this name is
 * referencing
 */
public record GoSymbolName(String symbolName, String packagePath, String packageName,
		String receiverString, String genericInfo, String baseName, String prefix,
		GoSymbolNameType symtype) {

	/**
	 * Fixes the specified string if it contains any of the golang special symbolname characters:
	 * middle-dot and the weird slash.
	 * 
	 * @param s string to fix
	 * @return original string, or fixed version
	 */
	public static String fixGolangSpecialSymbolnameChars(String s) {
		// "\u00B7" -> "."
		// "\u2215" -> "/"
		if (s.contains("\u00B7") || s.contains("\u2215")) {
			s = s.replaceAll("\u00B7", ".").replaceAll("\u2215", "/");
		}
		return s;
	}

	private static final Pattern TYPE_PREFIX_PATTERN =
		Pattern.compile("^(type[:.]\\.([a-z]+)\\.)(.*?[^\u00B7]+)(\u00B7[0-9]+)?$");
	
	private static final Pattern TYPE_PREFIX_SUB_PATTERN =
		Pattern.compile("^type[:.]\\.([a-z]+)\\.$");

	public static GoSymbolName parseTypeName(String s, String packagePath) {
		int endOfPrefix = indexOfAny(s, "*[]0123456789.", 0, false);
		if (endOfPrefix == -1) {
			endOfPrefix = 0;
		}
		String prefixStr = s.substring(0, endOfPrefix);
		
		s = s.substring(endOfPrefix);
		int typeNameLimit = indexOfAny(s, " {([", 0, true);
		if (typeNameLimit == -1) {
			typeNameLimit = s.length();
		}
		
		int packagePathEnd = s.lastIndexOf('/', typeNameLimit - 1);
		boolean foundAbsPkgPath = packagePathEnd >= 0;
		String packageStr = "";
		if (foundAbsPkgPath) {
			packageStr = s.substring(0, packagePathEnd + 1);
			s = s.substring(packagePathEnd + 1);
			typeNameLimit -= (packagePathEnd + 1);
		}
		
		int typeNameStart = s.lastIndexOf('.', typeNameLimit - 1);
		if ( typeNameStart >= 0 ) {
			packageStr += s.substring(0, typeNameStart);
			s = s.substring(typeNameStart + 1);
		}
		String typeName = s;
		
		if ( !foundAbsPkgPath && packagePath != null && !packagePath.isEmpty() && packagePath.endsWith(packageStr) ) {
			packageStr = packagePath;
		}
		
		String canonicalName = prefixStr + packageStr +
			(!packageStr.isEmpty() && !packageStr.endsWith("/") ? "." : "") + typeName;
		return new GoSymbolName(canonicalName, packageStr, extractPackageName(packageStr), null,
			null, typeName, prefixStr, GoSymbolNameType.DATA_TYPE);
	}

	public static GoSymbolName parse(String s) {
		GoSymbolName result = _parse(s);
		return result != null ? result : new GoSymbolName(s);
	}

	private static GoSymbolName _parse(String s) {
		if (s.startsWith("go:")) {
			// don't try to parse "go:...." symbols
			return null;
		}
		String origStr = s;

		// Special handling for "type:" .eq. and .hash. prefixes
		Matcher m = TYPE_PREFIX_PATTERN.matcher(s);
		if (m.matches()) {
			String prefixStr = m.group(1);
			String typeStr = m.group(3);
			GoSymbolName typeSN = parseTypeName(typeStr, "");
			return new GoSymbolName(s, typeSN.packagePath, typeSN.packageName, null, null, typeStr,
				prefixStr, GoSymbolNameType.FUNC);
		}

		s = fixGolangSpecialSymbolnameChars(origStr);

		int pkgInfoLimit = indexOfAny(s, "([");
		if (pkgInfoLimit == -1) {
			pkgInfoLimit = s.length();
		}

		// "d/p.(xxxx).yyyy.zzz" or "d/p.xxx" or "d/p.xxx[yyy].zzz" or "d/p.xxx.yyy.zzz"
		int lastSlash = s.lastIndexOf('/', pkgInfoLimit);
		int pkgDot = s.indexOf('.', lastSlash + 1);
		if (pkgDot < 0) {
			return null;
		}
		String pkgStr = s.substring(0, pkgDot);

		List<String> parts = splitNestedStringOn(s.substring(pkgDot + 1), '.');
		String firstPart = parts.get(0);
		int baseIndex = 0;

		String recvStr = null;
		String genericsStr = null;
		if (firstPart.startsWith("(") && firstPart.endsWith(")")) {
			String[] recvParts = splitGenerics(firstPart.substring(1, firstPart.length() - 1));
			recvStr = recvParts[0];
			genericsStr = recvParts[1];
			baseIndex++;
		}

		String baseSymbolName;
		if (baseIndex == 0 && parts.size() == 1) {
			// only consider generic string on normal func, not nested or lambdas
			String[] nameParts = splitGenerics(firstPart);
			baseSymbolName = nameParts[0];
			genericsStr = nameParts[1];
		}
		else {
			baseSymbolName = String.join(".", parts.subList(baseIndex, parts.size()));
		}
		GoSymbolNameType type = parts.size() == baseIndex + 1
				? GoSymbolNameType.fromNameWithDashSuffix(parts.get(parts.size() - 1))
				: GoSymbolNameType.fromNameSuffix(parts.get(parts.size() - 1));

		return new GoSymbolName(origStr, pkgStr, extractPackageName(pkgStr), recvStr, genericsStr,
			baseSymbolName, null, type);
	}

	private static String extractPackageName(String pkgStr) {
		// Extract package info from pkgStr
		// Will be in form of "pkgname", or "packagePath/packagedomain.org/path/pkgName"
		int pkgNameStart = pkgStr.lastIndexOf('/');
		return pkgNameStart != -1 ? pkgStr.substring(pkgNameStart + 1) : pkgStr;
	}

	/**
	 * Constructs a minimal GoSymbolName instance from the supplied values.
	 * 
	 * @param packageName package name, does not handle package paths, eg. "runtime"
	 * @param symbolName full symbol name, eg. "runtime.foo"
	 * @return new GoSymbolName instance
	 */
	public static GoSymbolName from(String packageName, String symbolName) {
		return new GoSymbolName(symbolName, packageName, packageName, null, null, null, null, null);
	}

	/**
	 * Constructs a GoSymbolName instance that only has a package path / package name.
	 * 
	 * @param packagePath package path to parse
	 * @return GoSymbolName that only has a package path and package name value
	 */
	public static GoSymbolName fromPackagePath(String packagePath) {
		GoSymbolName tmp = parse(packagePath + ".TMP");
		return new GoSymbolName(null, tmp.getPackagePath(), tmp.getPackageName(), null, null, null,
			null, null);
	}

	private GoSymbolName(String symbolName) {
		this(symbolName, null, null, null, null, null, null, GoSymbolNameType.UNKNOWN);
	}

	public boolean isMethod() {
		return receiverString != null;
	}

	public boolean hasGenerics() {
		return genericInfo != null;
	}

	public boolean isUnparsed() {
		return packagePath == null;
	}

	public boolean isAnonType() {
		return baseName != null && baseName.startsWith("struct { ");
	}

	/**
	 * Returns the portion the symbol name that is the packagePath (path+packagename), or null
	 * @return the portion the symbol name that is the packagePath (path+packagename), or null
	 */
	public String getPackagePath() {
		return packagePath;
	}

	/**
	 * Returns portion of the symbol name that is the package name, or null
	 * @return portion of the symbol name that is the package name, or null
	 */
	public String getPackageName() {
		return packageName;
	}

	public boolean hasReceiver() {
		return receiverString != null;
	}

	/**
	 * Returns portion of the symbol name that is the receiver string, or null
	 * @return portion of the symbol name that is the receiver string, or null
	 */
	public String getReceiverString() {
		return receiverString == null || genericInfo == null || genericInfo.isEmpty()
				? receiverString
				: "%s[%s]".formatted(receiverString, genericInfo);
	}

	public String getReceiverString(String modifiedGenerics) {
		return receiverString == null || modifiedGenerics == null || modifiedGenerics.isEmpty()
				? receiverString
				: "%s[%s]".formatted(receiverString, modifiedGenerics);
	}
	
	public GoSymbolName getReceiverTypeName() {
		return GoSymbolName.parseTypeName(getReceiverString(), getPackagePath());
	}

	public GoSymbolName getReceiverTypeName(String modifiedGenerics) {
		return GoSymbolName.parseTypeName(getReceiverString(modifiedGenerics), getPackagePath());
	}

	private static final String GO_SHAPE_PREFIX = "go.shape.";

	public String getShapelessGenericsString() {
		if (genericInfo == null) {
			return null;
		}
		List<String> genericParts = getGenericParts();
		return genericParts.stream()
				.map(s -> s.startsWith(GO_SHAPE_PREFIX) ? s.substring(GO_SHAPE_PREFIX.length()) : s)
				.collect(Collectors.joining(","));
	}

	public String getStrippedReceiverString() {
		return receiverString;
	}

	public String getGenericsString() {
		return genericInfo;
	}

	public List<String> getGenericParts() {
		return splitNestedStringOn(genericInfo, ',');
	}

	public String getStrippedSymbolString() {
		if (packagePath == null) {
			// unparsed/unsupported symbol name format
			return symbolName;
		}
		return isMethod()
				? "%s.(%s).%s".formatted(packagePath, getStrippedReceiverString(), baseName)
				: "%s.%s".formatted(packagePath, baseName);
	}

	/**
	 * Returns a new {@link GoSymbolName} instance with the current instance's information
	 * (which should be without receiver info) re-interpreted to be a non-pointer receiver symbol.
	 * <p>
	 * Example, symbol "package.name1.name2" would normally be parsed as a non-receiver symbol
	 * with a complex basename of "name1.name2", and this method will return a version
	 * that is equivalent of "package.(name1).name2".
	 *  
	 * @return new {@link GoSymbolName}
	 */
	public GoSymbolName asNonPtrReceiverSymbolName() {
		int dotIndex = baseName != null ? baseName.indexOf('.') : -1;
		if (dotIndex == -1) {
			return null;
		}
		String newRecv = baseName.substring(0, dotIndex);
		String newBase = baseName.substring(dotIndex + 1);
		GoSymbolNameType newType =
			newBase.endsWith("-fm") ? GoSymbolNameType.METHOD_WRAPPER : symtype;
		return new GoSymbolName(symbolName, packagePath, packageName, newRecv, genericInfo, newBase,
			prefix, newType);
	}

	public boolean isNonPtrReceiverCandidate() {
		int dotIndex = baseName != null ? baseName.indexOf('.') : -1;
		return dotIndex != -1 && baseName.lastIndexOf('.') == dotIndex; // there is only 1 '.'
	}

	/**
	 * Returns the full name of the golang symbol
	 * @return full name of the golang symbol
	 */
	public String asString() {
		return symbolName;
	}

	@Override
	public final String toString() {
		return symbolName;
	}

	public String getBaseName() {
		return baseName;
	}
	
	public String getBaseTypeName() {
		return Objects.requireNonNullElse(prefix, "") + baseName;
	}

	public GoSymbolNameType getNameType() {
		return symtype;
	}

	public String getPrefix() {
		return prefix;
	}

	public String getTypePrefixSubKeyword() {
		Matcher m = TYPE_PREFIX_SUB_PATTERN.matcher(Objects.requireNonNullElse(prefix, ""));
		if (m.matches()) {
			return m.group(1);
		}
		return null;
	}

	/**
	 * Returns the portion of the package path before the package name, eg. "internal/sys" would
	 * become "internal/".
	 * 
	 * @return package path, without the trailing package name, or empty string if there is no path 
	 * portion of the string
	 */
	public String getTruncatedPackagePath() {
		return packagePath != null && packageName != null &&
			packagePath.length() > packageName.length()
					? packagePath.substring(0, packagePath.length() - packageName.length())
					: null;
	}

	/**
	 * Returns a Ghidra {@link Namespace} based on the golang package path.
	 * 
	 * @param program {@link Program} that will contain the namespace
	 * @return {@link Namespace} cooresponding to the golang package path, or the program's root
	 * namespace if no package path information is present
	 */
	public Namespace getSymbolNamespace(Program program) {
		Namespace rootNS = program.getGlobalNamespace();
		if (packagePath != null && !packagePath.isBlank()) {
			try {
				return program.getSymbolTable()
						.getOrCreateNameSpace(rootNS, packagePath, SourceType.IMPORTED);
			}
			catch (DuplicateNameException | InvalidInputException e) {
				// ignore, fall thru
			}
		}
		return rootNS;
	}

	/**
	 * Returns the matching Ghidra function (based on namespace and symbol name).
	 * 
	 * @param program {@link Program} containing the function
	 * @return Ghidra {@link Function}
	 */
	public Function getFunction(Program program) {
		Namespace ns = getSymbolNamespace(program);
		Symbol sym = SymbolUtilities.getUniqueSymbol(program, asString(), ns);
		Function func = sym instanceof FunctionSymbol ? (Function) sym.getObject() : null;
		return func;
	}

	//---------------------------------------------------------------------------------------------

	private static int indexOfAny(String s, String chars) {
		return indexOfAny(s, chars, 0, true);
	}

	private static int indexOfAny(String s, String chars, int start, boolean charsMatch) {
		for (int i = start; i < s.length(); i++) {
			char ch = s.charAt(i);
			boolean matches = chars.indexOf(ch) != -1;
			if (matches == charsMatch) {
				return i;
			}
		}
		return -1;
	}

	private static final Map<Character, Character> NESTING_ENDCHARS =
		Map.of('{', '}', '(', ')', '[', ']');

	/**
	 * splits a string on occurrences of a specific char at the 'top' level of the string, ignoring
	 * the split char when found inside of nested delimited sections of the string.
	 * <p>
	 * Nesting is delimited by '(', '{', '[' chars and their matching closing element.
	 *  
	 * @param s string to split
	 * @param splitChar char to split the string on
	 * @return list of strings that are each part of the original string
	 */
	private static List<String> splitNestedStringOn(String s, char splitChar) {
		// TODO: may also have to skip chars in quoted field comments 
		List<String> parts = new ArrayList<>();
		Deque<Character> nestingstack = new ArrayDeque<>();
		int partStart = 0;
		for (int i = 0; i < s.length();) {
			int codePoint = s.codePointAt(i);
			switch (codePoint) {
				case '{', '(', '[':
					nestingstack.addLast(NESTING_ENDCHARS.get((char) codePoint));
					break;
				case '}', ')', ']':
					Character expectedEndChar = nestingstack.pollLast();
					if (expectedEndChar == null || (char) expectedEndChar != (char) codePoint) {
						return List.of(s); // failed to successfully split the string
					}
					break;
				default:
					if (codePoint == splitChar) {
						if (nestingstack.isEmpty()) {
							parts.add(s.substring(partStart, i));
							partStart = i + 1; // skip the comma (we know the codepoint len == 1)
						}
					}
			}
			i += Character.charCount(codePoint);
		}
		parts.add(s.substring(partStart));
		return parts;
	}

	static String[] splitGenerics(String s) {
		String[] result = new String[] { null, null };
		int genStart = s.indexOf('[');
		if (genStart != -1 && s.endsWith("]")) {
			result[0] = s.substring(0, genStart);
			result[1] = s.substring(genStart + 1, s.length() - 1);
		}
		else {
			result[0] = s;
		}
		return result;
	}

}
