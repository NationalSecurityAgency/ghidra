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

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ClassSearcher;

/**
 * Demangler Utility class.  For version 11.3, we have migrated to a new Demangler API that
 * requires a {@link MangledContext} be passed to the demangler.  This provides more information
 * for properly demangling symbols.
 * <p>
 * Two methods below have been deprecated, as they do not provide enough information to produce
 * the {@link MangledContext}.  A new method @link demangle(Program, String, Address) is provided
 * to permit proper operation using a completed context.  Moreover, this new method returns all
 * results instead of the first one found, as is how the deprecated methods work.
 */
public class DemanglerUtil {

	//
	// Patterns used to remove superfluous spaces within parameter list.
	//
	private static final Pattern LEADING_PARAMETER_SPACE_PATTERN =
		Pattern.compile(" ([\\*\\&\\)])");
	private static final Pattern TRAILING_PARAMETER_SPACE_PATTERN = Pattern.compile("([\\(\\,]) ");

	/**
	 * Deprecated.  Use {@link #demangle(Program, String, Address)}. See class header for more
	 * details.
	 *
	 * Locates all available demanglers, then it attempts to demangle.  This method will
	 * query all demanglers regardless of architecture.
	 *
	 * <p>This method will use only the default options for demangling.  If you need to
	 * specify options, then you will have to call each specific demangler directly, creating
	 * the options and mangled context specifically needed for each demangler.   See
	 * {@link Demangler#createMangledContext(String, DemanglerOptions, Program, Address)} and
	 * {@link Demangler#createDefaultOptions()}.
	 *
	 * @param mangled the mangled name
	 * @return the demangled object or null
	 * @deprecated see above
	 */
	@Deprecated(since = "11.3", forRemoval = true)
	public static DemangledObject demangle(String mangled) {
		List<Demangler> demanglers = getDemanglers();
		for (Demangler demangler : demanglers) {
			try {
				MangledContext mangledContext =
					demangler.createMangledContext(mangled, null, null, null);
				DemangledObject demangledObject = demangler.demangle(mangledContext);
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
	 * Deprecated.  Use {@link #demangle(Program, String, Address)}. See class header for more
	 * details.
	 *
	 * <p>Locates all available demanglers and checks to see if the supplied program is
	 * supported, then it attempts to demangle.
	 *
	 * <p>This method will use only the default options for demangling.  If you need to
	 * specify options, then you will have to call each specific demangler directly, creating
	 * the options and mangled context specifically needed for each demangler.   See
	 * {@link Demangler#createMangledContext(String, DemanglerOptions, Program, Address)} and
	 * {@link Demangler#createDefaultOptions()}.
	 *
	 * @param program the program containing the mangled name
	 * @param mangled the mangled name
	 * @return the demangled object or null
	 * @deprecated see above
	 */
	@Deprecated(since = "11.3", forRemoval = true)
	public static DemangledObject demangle(Program program, String mangled) {
		List<Demangler> demanglers = getDemanglers();
		for (Demangler demangler : demanglers) {
			try {
				if (!demangler.canDemangle(program)) {
					continue;
				}

				MangledContext mangledContext =
					demangler.createMangledContext(mangled, null, null, null);
				DemangledObject demangledObject = demangler.demangle(mangledContext);
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
	 * supported, then it attempts to demangle.  Returns a list of {@link DemangledObject} of
	 * successful demanglings
	 *
	 * <p>This method will use only the default options for demangling.  If you need to
	 * specify options, then you will have to call each specific demangler directly, creating
	 * the options and mangled context specifically needed for each demangler.   See
	 * {@link Demangler#createMangledContext(String, DemanglerOptions, Program, Address)} and
	 * {@link Demangler#createDefaultOptions()}.
	 *
	 * @param program the program containing the mangled name; can be null
	 * @param mangled the mangled name
	 * @param address the address of the mangled name; can be null
	 * @return the list of {@link DemangledObject}
	 */
	public static List<DemangledObject> demangle(Program program, String mangled, Address address) {
		List<DemangledObject> results = new ArrayList<>();
		List<Demangler> demanglers = getDemanglers();
		for (Demangler demangler : demanglers) {
			try {
				if (!demangler.canDemangle(program)) {
					continue;
				}

				MangledContext mangledContext =
					demangler.createMangledContext(mangled, null, program, address);
				DemangledObject demangledObject = demangler.demangle(mangledContext);
				if (demangledObject != null) {
					results.add(demangledObject);
				}
			}
			catch (DemangledException e) {
				// ignore
			}
		}
		return results;
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
