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
package ghidra.app.util.demangler;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ClassSearcher;

public class DemanglerUtil {

	//
	// Patterns used to remove superfluous spaces within parameter list. 
	//
	private static final Pattern LEADING_PARAMETER_SPACE_PATTERN =
		Pattern.compile(" ([\\*\\&\\)])");
	private static final Pattern TRAILING_PARAMETER_SPACE_PATTERN = Pattern.compile("([\\(\\,]) ");

	/**
	 * Locates all available demanglers, then it attempts to demangle.  This method will
	 * query all demanglers regardless of architecture.  
	 * 
	 * <p>This method will use only the default options for demangling.  If you need to 
	 * specify options, then you will have to call each specific demangler directly, creating
	 * the options specifically needed for each demangler.   See 
	 * {@link Demangler#createDefaultOptions()}.
	 * 
	 * @param mangled the mangled name
	 * @return the demangled object or null
	 */
	public static DemangledObject demangle(String mangled) {
		List<Demangler> demanglers = getDemanglers();
		for (Demangler demangler : demanglers) {
			try {
				DemangledObject demangledObject = demangler.demangle(mangled);
				if (demangledObject != null) {
					return demangledObject;
				}
			}
			catch (DemangledException e) {
				// ignore
			}
		}
		return null;
	}

	/**
	 * Locates all available demanglers and checks to see if the supplied program is 
	 * supported, then it attempts to demangle.
	 * 
	 * <p>This method will use only the default options for demangling.  If you need to 
	 * specify options, then you will have to call each specific demangler directly, creating
	 * the options specifically needed for each demangler.   See 
	 * {@link Demangler#createDefaultOptions()}.
	 * 
	 * @param program the program containing the mangled name
	 * @param mangled the mangled name
	 * @return the demangled object or null
	 */
	public static DemangledObject demangle(Program program, String mangled) {
		List<Demangler> demanglers = getDemanglers();
		for (Demangler demangler : demanglers) {
			try {
				if (!demangler.canDemangle(program)) {
					continue;
				}

				DemangledObject demangledObject = demangler.demangle(mangled);
				if (demangledObject != null) {
					return demangledObject;
				}
			}
			catch (DemangledException e) {
				// ignore
			}
		}
		return null;
	}

	/**
	 * Dynamically locates all available demangler implementations.
	 * 
	 * @return a list of all demanglers
	 */
	private static List<Demangler> getDemanglers() {
		return ClassSearcher.getInstances(Demangler.class);
	}

	/**
	 * Remove superfluous function signature spaces from specified string
	 * @param str string
	 * @return string with unwanted spaces removed
	 */
	public static String stripSuperfluousSignatureSpaces(String str) {
		return replace(replace(str, LEADING_PARAMETER_SPACE_PATTERN),
			TRAILING_PARAMETER_SPACE_PATTERN);
	}

	private static String replace(String str, Pattern spaceCleanerPattern) {
		Matcher matcher = spaceCleanerPattern.matcher(str);
		StringBuilder buffy = new StringBuilder();
		while (matcher.find()) {
			String captureGroup = matcher.group(1);
			matcher.appendReplacement(buffy, captureGroup);
		}
		matcher.appendTail(buffy);
		return buffy.toString();
	}
}
