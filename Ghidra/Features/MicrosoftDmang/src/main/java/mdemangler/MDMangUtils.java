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
package mdemangler;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.util.SymbolPath;
import ghidra.app.util.SymbolPathParser;
import mdemangler.datatype.complex.MDComplexType;
import mdemangler.datatype.modifier.MDModifierType;
import mdemangler.naming.*;
import mdemangler.object.MDObjectCPP;

/**
 * Utility class for MDMang users (and perhaps internal)
 */
public class MDMangUtils {

	private MDMangUtils() {
		// purposefully empty
	}

	/**
	 * Returns SymbolPath for the demangled item
	 * @param parsableItem the demangled item
	 * @return the symbol path
	 */
	public static SymbolPath getSymbolPath(MDParsableItem parsableItem) {
		return getSymbolPath(parsableItem, false);
	}

	/**
	 * Returns a more simple SymbolPath for the demangled item.  Any embedded object found at
	 * the main namespace level will have its namespace components retrieved and inserted
	 * appropriately in the main SymbolPath namespace.  However, embedded objects that are more
	 * deeply placed (such as when used for a template argument) don't and shouldn't take part
	 * in this simplification
	 * @param parsableItem the demangled item
	 * @return the symbol path
	 */
	public static SymbolPath getSimpleSymbolPath(MDParsableItem parsableItem) {
		return getSymbolPath(parsableItem, true);
	}

	private static SymbolPath getSymbolPath(MDParsableItem parsableItem, boolean simple) {
		List<String> parts = new ArrayList<>();
		// When simple is true, we need to recurse the nested hierarchy to pull the names
		// up to the main namespace level, so we set recurse = true
		recurseNamespace(parts, parsableItem, simple);
		SymbolPath sp = null;
		for (String part : parts) {
			sp = new SymbolPath(sp, part);
		}
		return sp;
	}

	private static void recurseNamespace(List<String> parts, MDParsableItem item,
			boolean recurseNested) {
		item = getReferencedType(item);
		String name;
		MDQualification qualification;
		if (item instanceof MDComplexType complexType) {
			MDQualifiedName qualName = complexType.getNamespace();
			name = qualName.getName();
			qualification = qualName.getQualification();
		}
		else if (item instanceof MDObjectCPP objCpp) {
			MDObjectCPP embeddedObj = objCpp.getEmbeddedObject();
			name = embeddedObj.getName();
			qualification = embeddedObj.getQualification();
		}
		else {
			return;
		}

		List<String> myParts = new ArrayList<>();
		// the qualification comes in reverse order... the last is nearest to namespace root
		for (MDQualifier qual : qualification) {
			if (qual.isNested() && recurseNested) {
				MDNestedName nestedName = qual.getNested();
				MDObjectCPP nestedObjCpp = nestedName.getNestedObject();
				List<String> nestedParts = new ArrayList<>();
				recurseNamespace(nestedParts, nestedObjCpp, recurseNested);
				myParts.addAll(0, nestedParts);
			}
			else if (qual.isAnon()) {
				// Instead of using the standard qual.toString() method, which returns
				// "`anonymous namespace'" for anonymous qualifiers, we use qual.getAnonymousName()
				// which will have the underlying anonymous name of the form "A0xfedcba98" to create
				// a standardized anonymous name that is distinguishable from other anonymous names.
				// The standardized name comes from createStandardAnonymousNamespaceNode().  This
				// is especially important when there are sibling anonymous names.
				String anon = createStandardAnonymousNamespaceNode(qual.getAnonymousName());
				myParts.add(0, anon);
			}
			else {
				myParts.add(0, stripTags(qual.toString()));
			}
		}
		myParts.add(stripTags(name));
		parts.addAll(myParts);
	}

	// This method recurses
	private static MDParsableItem getReferencedType(MDParsableItem item) {
		if (item instanceof MDModifierType m) {
			return getReferencedType(m.getReferencedType());
		}
		return item;
	}

	/**
	 * Checks that the given String begins with standard "A0x" (under-the-hood MDMang name)
	 *  pattern or with the "`" pattern that is found with MDQuestionModifier type
	 * @param anon the input string or the original string if is not standard
	 * @return the standardized anonymous namespace component
	 */
	public static String createStandardAnonymousNamespaceNode(String anon) {
		/*
		 * Note that we are converting to upper case and doing zero padding to 8 hex digits.
		 * Rationale:  In analyzing mangled symbols with anonymous namespaces, we found an LLVM
		 * PDB that had a mix of anonymous namespaces:
		 *  that used only lower case a-f hex digits
		 *  that used only upper case A-F hex digits
		 *  that had zero-padding, leading zeros to 8 hex digits
		 *  that did not have zero-padding, leading zeros to 8 hex digits
		 * There were matching namespaces between upper-case-only hex and lower-case-only that were
		 *  found often enough to be beyond coincidence.
		 * There was only one anon NS node that had the zero-padding and this is one that also
		 *  had the 8-hex-digit suffix that we (have initially) parsed in the MDQuestionmodifier
		 *  type.  Knowing that this matches has, for all practical purposes, confirmed that the
		 *  suffix is to represent an anonymous namespace.
		 * Since there was only one anon NS with zero padding, we could not convince ourselves
		 *  completely that a "short" namespace and one with leading zeros that shared the
		 *  meaningful numeric part were essentially the same, but it would make sense to assume
		 *  this is true, especially in the context of the 8-hex digit suffix case (the need for
		 *  this suffix is probably what causes the namespace to be created, and it uses formatting
		 *  that provides the zero-padding; later, when the A0x namespace is needed, it uses the
		 *  name already given)
		 * TODO: probably want to wind this into special MDMang processing as some sort of option
		 *  and possibly an optional user-specified format.
		 */
		String str;
		if (anon.startsWith("A0x")) {
			str = anon.substring(3);
		}
		else if (anon.startsWith("`")) {
			str = anon.substring(1);
		}
		else {
			return anon;
		}
		Long num = Long.valueOf(str, 16);
		return String.format("_anon_%08X", num);
	}

	/**
	 * Given a number in string format as input, creates the standardized local namespace
	 *  node string of the format {@code __l2} where {@code 2} is an an example number.
	 * @param localNumber the input string
	 * @return the standardized local namespace component
	 */
	public static String createStandardLocalNamespaceNode(String localNumber) {
		return String.format("__l%s", localNumber);
	}

	// @formatter:off
	private static String[] searchList = {
		"<class ", "<struct ", "<union ", "<coclass ", "<cointerface ", "<enum ",
		"(class ", "(struct ", "(union ", "(coclass ", "(cointerface ", "(enum ",
		"`class ", "`struct ", "`union ", "`coclass ", "`cointerface ", "`enum ",
		",class ", ",struct ", ",union ", ",coclass ", ",cointerface ", ",enum ",
		" __ptr64", "__unaligned ", " __restrict"}; // purposeful trailing space on "__unaligned "

	private static String[] replacementList = {
		"<", "<", "<", "<", "<", "<",
		"(", "(", "(", "(", "(", "(",
		",", "`", "`", "`", "`", "`",
		",", ",", ",", ",", ",", ",",
		"",  "", ""};
	// @formatter:on

	// Quick and dirty way to do this... We need to work on MDMang object model
	//  and then add control (MDControl) to emit methods (insert(), append(), other,
	//  and probably need to rework/replace these too)
	private static String stripTags(String str) {
		return StringUtils.replaceEach(str, searchList, replacementList);
	}

	public static SymbolPath consolidateSymbolPath(MDParsableItem parsableItem,
			String regularPathName, boolean simple) {
		List<String> demangledParts = new ArrayList<>();
		// When simple is true, we need to recurse the nested hierarchy to pull the names
		// up to the main namespace level, so we set recurse = true
		recurseNamespace(demangledParts, parsableItem, simple);
		List<String> regularParts = SymbolPathParser.parse(regularPathName);

		int m = Integer.min(demangledParts.size(), regularParts.size());

		List<String> parts = new ArrayList<>();
		for (int i = 1; i <= m; i++) {
			int ni = demangledParts.size() - i;
			String n = demangledParts.get(ni);
			// Prefer the mangled part, but could get more sophisticated and decide to use
			// regular parts too
			parts.add(0, n);
		}
		for (int i = m + 1; i <= regularParts.size(); i++) {
			int ri = regularParts.size() - i;
			String r = regularParts.get(ri);
			if (r.equals("`anonymous-namespace'")) {
				parts.add(0, "`anonymous namespace'");
			}
			else {
				parts.add(0, r);
			}
		}
		for (int i = m + 1; i <= demangledParts.size(); i++) {
			int ni = demangledParts.size() - i;
			String n = demangledParts.get(ni);
			parts.add(0, n);
		}

		SymbolPath sp = null;
		for (String part : parts) {
			sp = new SymbolPath(sp, part);
		}
		return sp;
	}

	private static final Pattern LOCAL_NS_PATTERN = Pattern.compile("^__l([0-9]+)$");
	private static final Pattern EMBEDDED_LOCAL_NS_PATTERN = Pattern.compile("::__l([0-9]+)::");
	private static final Pattern DEMANGLED_LOCAL_NS_PATTERN = Pattern.compile("^`([0-9]+)'$");
	private static final Pattern DEMANGLED_EMBEDDED_LOCAL_NS_PATTERN =
		Pattern.compile("::`([0-9]+)'::");

	/**
	 * Standardize a SymbolPath.  For now replacing local namespace {@code __l#} pattern with
	 * {@code `#'} pattern.
	 * <p> Ultimately, this method should be moved to a different utility class, but putting it
	 * here for now (probably with the template work)
	 * @param symbolPath the symbol path to standardize
	 * @return the standardized symbol path
	 */
	public static SymbolPath standarizeSymbolPathTicks(SymbolPath symbolPath) {
		List<String> parts = symbolPath.asList();
		for (int i = 0; i < parts.size(); i++) {
			String part = parts.get(i);
			// These anonymous namespaces are those that come in the clear (non-mangled)
			StringUtils.replace(part, "`anonymous-namespace'", "`anonymous namespace'");
			StringBuilder sb = new StringBuilder();
			Matcher m = LOCAL_NS_PATTERN.matcher(part);
			if (m.find()) {
				m.appendReplacement(sb, "`" + m.group(1) + "'");
			}
			else {
				m = EMBEDDED_LOCAL_NS_PATTERN.matcher(part);
				while (m.find()) {
					m.appendReplacement(sb, "::`" + m.group(1) + "'::");
				}
				m.appendTail(sb);
			}
			if (!sb.isEmpty()) {
				parts.set(i, sb.toString());
			}
		}
		return new SymbolPath(parts);
	}

	/**
	 * Standardize a SymbolPath.  Alternative: replacing local namespace {@code `#'} pattern with
	 * {@code __l#} pattern.
	 * <p> Ultimately, this method should be moved to a different utility class, but putting it
	 * here for now (probably with the template work)
	 * @param symbolPath the symbol path to standardize
	 * @return the standardized symbol path
	 */
	public static SymbolPath standarizeSymbolPathUnderscores(SymbolPath symbolPath) {
		List<String> parts = symbolPath.asList();
		for (int i = 0; i < parts.size(); i++) {
			String part = parts.get(i);
			// These anonymous namespaces are those that come in the clear (non-mangled)
			StringUtils.replace(part, "`anonymous-namespace'", "`anonymous namespace'");
			StringBuilder sb = new StringBuilder();
			Matcher m = DEMANGLED_LOCAL_NS_PATTERN.matcher(part);
			if (m.find()) {
				m.appendReplacement(sb, "__l" + m.group(1));
			}
			else {
				m = DEMANGLED_EMBEDDED_LOCAL_NS_PATTERN.matcher(part);
				while (m.find()) {
					m.appendReplacement(sb, "::__l" + m.group(1) + "::");
				}
				m.appendTail(sb);
			}
			if (!sb.isEmpty()) {
				parts.set(i, sb.toString());
			}
		}
		return new SymbolPath(parts);
	}

}
