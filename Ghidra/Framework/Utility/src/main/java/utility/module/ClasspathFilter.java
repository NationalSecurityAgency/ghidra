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
package utility.module;

import java.io.File;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Predicate;

import generic.jar.ResourceFile;
import ghidra.framework.GModule;

/**
 * A predicate used to filter modules using the classpath.   Only modules included in the classpath
 * will pass this filter.  Any modules not on the classpath may be included by calling
 * {@link #ClasspathFilter(Predicate)} with a predicate that allows other module paths.
 */
public class ClasspathFilter implements Predicate<GModule> {

	private Predicate<Path> additionalPaths = p -> false;
	private Set<Path> cpModulePaths = new HashSet<>();

	/**
	 * Default constructor to allow only modules on the classpath.
	 */
	public ClasspathFilter() {
		String cp = System.getProperty("java.class.path");
		String[] cpPathStrings = cp.split(File.pathSeparator);
		for (String cpPathString : cpPathStrings) {
			Path modulePath = ModuleUtilities.getModule(cpPathString);
			if (modulePath != null) {
				Path normalized = modulePath.normalize().toAbsolutePath();
				cpModulePaths.add(normalized);
			}
		}
	}

	/**
	 * Constructor that allows any module to be included whose path passed the given predicate.  If
	 * the predicate returns false, then a given module will only be included if it is in the
	 * classpath.
	 *
	 * @param additionalPaths a predicate that allows additional module paths (they do not need to
	 *   be on the system classpath)
	 */
	public ClasspathFilter(Predicate<Path> additionalPaths) {
		this();
		this.additionalPaths = additionalPaths;
	}

	@Override
	public boolean test(GModule m) {
		ResourceFile file = m.getModuleRoot();
		Path path = Path.of(file.getAbsolutePath());
		Path normalized = path.normalize().toAbsolutePath();
		return additionalPaths.test(normalized) || cpModulePaths.contains(normalized);
	}

}
