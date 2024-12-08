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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Represents a Golang symbol name.
 * 
 * @param symbolName full name of the golang symbol
 * @param packagePath portion the symbol name that is the packagePath (path+packagename), or null
 * @param packageName portion of the symbol name that is the package name, or null
 * @param receiverString portion of the symbol name that is the receiver string (only found when
 * the receiver is in the form of "(*typename)"), or null
 */
public record GoSymbolName(String symbolName, String packagePath, String packageName,
		String receiverString) {

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

	/**
	 * Matches golang symbol strings such as:
	 * "package/domain.name/packagename.(*ReceiverTypeName).Functionname"
	 * or
	 * "type:.eq.[39]package/domain.name/packagename.Functionname"
	 */
	private static final Pattern SYMBOL_INFO_PATTERN = Pattern.compile(
		// "type:" ".eq." or ".hash.", optional slice "[numbers_or_dots]",
		"^(type:\\.(eq|hash)\\.(\\[[0-9.]*\\])?)?" +
			// package_path/package_name.(*optional_receiverstring)remainder_of_symbol_string
			"(([-+_/.a-zA-Z0-9]+)(\\(\\*[^)]+\\))?.*)");

	/**
	 * Parses a golang symbol string and returns a GoSymbolName instance.
	 * 
	 * @param s string to parse
	 * @return new GoSymbolName instance, never null
	 */
	public static GoSymbolName parse(String s) {

		s = fixGolangSpecialSymbolnameChars(s);

		Matcher m = SYMBOL_INFO_PATTERN.matcher(s);
		if (s.startsWith("go:") || !m.matches()) {
			return new GoSymbolName(s);
		}

		String packageString = m.group(5);
		String receiverString = m.group(6);

		int packageNameStart = packageString.lastIndexOf('/') + 1;
		int firstDot = packageString.indexOf('.', packageNameStart);
		if (firstDot <= 0) {
			return new GoSymbolName(s);
		}
		String packagePath = packageString.substring(0, firstDot);
		String packageName = packageString.substring(packageNameStart, firstDot);
		if (receiverString != null && !receiverString.isEmpty()) {
			receiverString = receiverString.substring(1, receiverString.length() - 1);
		}
		return new GoSymbolName(s, packagePath, packageName, receiverString);
	}

	/**
	 * Constructs a minimal GoSymbolName instance from the supplied values.
	 * 
	 * @param packageName package name, does not handle package paths, eg. "runtime"
	 * @param symbolName full symbol name, eg. "runtime.foo"
	 * @return new GoSymbolName instance
	 */
	public static GoSymbolName from(String packageName, String symbolName) {
		return new GoSymbolName(symbolName, packageName, packageName, null);
	}

	/**
	 * Constructs a GoSymbolName instance that only has a package path / package name.
	 * 
	 * @param packagePath package path to parse
	 * @return GoSymbolName that only has a package path and package name value
	 */
	public static GoSymbolName fromPackagePath(String packagePath) {
		GoSymbolName tmp = parse(packagePath + ".TMP");
		return new GoSymbolName(null, tmp.getPackagePath(), tmp.getPackageName(), null);
	}

	private GoSymbolName(String symbolName) {
		this(symbolName, null, null, null);
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

	/**
	 * Returns portion of the symbol name that is the receiver string (only found when
	 * the receiver is in the form of "(*typename)"), or null
	 * @return portion of the symbol name that is the receiver string (only found when
	 * the receiver is in the form of "(*typename)"), or null
	 */
	public String getRecieverString() {
		return receiverString;
	}

	/**
	 * Returns the full name of the golang symbol
	 * @return full name of the golang symbol
	 */
	public String getSymbolName() {
		return symbolName;
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
		Symbol sym = SymbolUtilities.getUniqueSymbol(program, getSymbolName(), ns);
		Function func = sym instanceof FunctionSymbol ? (Function) sym.getObject() : null;
		return func;
	}

}
