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
package ghidra;

import java.io.File;
import java.lang.instrument.Instrumentation;
import java.net.*;
import java.util.*;

import ghidra.util.Msg;

/**
 * Custom Ghidra URL class loader which exposes the addURL method so we can add to the classpath
 * at runtime.  
 * <p>
 * This class loader must be installed by setting the "java.system.class.loader" 
 * system property prior to launch (i.e., the JVM should be launched with the following argument:
 * -Djava.system.class.loader=ghidra.GhidraClassLoader.
 * 
 */
public class GhidraClassLoader extends URLClassLoader {

	/**
	 * When 'true', this property will trigger the system to put each Extension module's lib jar 
	 * files into the {@link #CP_EXT} property.
	 */
	public static final String ENABLE_RESTRICTED_EXTENSIONS_PROPERTY =
		"ghidra.extensions.classpath.restricted";

	/**
	 * The classpath system property: {@code java.class.path}
	 */
	public static final String CP = "java.class.path";

	/**
	 * The extensions classpath system property: {@code java.class.path.ext}
	 */
	public static final String CP_EXT = "java.class.path.ext";

	/**
	 * Gets a {@link List} containing the current classpath referenced by the given property name
	 * 
	 * @param propertyName The property name of the classpath to get
	 * @return A {@link List} containing the current classpath referenced by the given property name
	 */
	public static List<String> getClasspath(String propertyName) {
		List<String> result = new ArrayList<>();

		// StringTokenizer is better than split() here because our result list will stay empty if
		// the classpath is empty
		StringTokenizer st =
			new StringTokenizer(System.getProperty(propertyName, ""), File.pathSeparator);
		while (st.hasMoreTokens()) {
			result.add(st.nextToken());
		}
		return result;
	}

	/**
	 * Used to prevent duplicate URL's from being added to the classpath
	 */
	private Set<URL> alreadyAdded = new HashSet<>();

	/**
	 * This one-argument constructor is required for the JVM to successfully use this class loader
	 * via the java.system.class.loader system property.
	 * 
	 * @param parent The parent class loader for delegation
	 */
	public GhidraClassLoader(ClassLoader parent) {
		super(new URL[0], parent);
	}

	@Override
	public void addURL(URL url) {
		if (!alreadyAdded.add(url)) {
			return;
		}
		super.addURL(url);
		try {
			System.setProperty(CP,
				System.getProperty(CP) + File.pathSeparatorChar + new File(url.toURI()));
		}
		catch (URISyntaxException e) {
			Msg.debug(this, "URL is not a valid path: " + url);
		}
	}

	/**
	 * Converts the specified path to a {@link URL} and adds it to the classpath.
	 *
	 * @param path The path to be added.
	 * @return True if the path was successfully added; otherwise, false.  Failure can occur if the 
	 *   path is not able to be converted to a URL.
	 * @see #addURL(URL)
	 */
	public boolean addPath(String path) {
		try {
			addURL(new File(path).toURI().toURL());
			return true;
		}
		catch (MalformedURLException e) {
			return false;
		}
	}

	/**
	 * VisualVM calls this to dynamically add things to the classpath.  
	 * <p>
	 * NOTE: It is not required to be public.
	 *  
	 * @param path The path to be added to the search path of URLs.
	 * @see Instrumentation#appendToSystemClassLoaderSearch
	 */
	@SuppressWarnings("unused")
	private void appendToClassPathForInstrumentation(String path) {
		addPath(path);
	}
}
