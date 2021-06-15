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
package ghidra.app.plugin.core.osgi;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.*;
import java.util.*;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.felix.framework.util.manifestparser.ManifestParser;
import org.osgi.framework.*;
import org.osgi.framework.wiring.BundleCapability;
import org.osgi.framework.wiring.BundleRequirement;

import ghidra.util.Msg;

public class OSGiUtils {
	/*
	 * Match group 1 contains the file name from a resource string, e.g.  from
	 *     file:/path/to/some.jar!/Some.class
	 * we get "/path/to/some.jar", everything between ':' and '!'
	 * 
	 */
	private static Pattern JAR_FILENAME_EXTRACTOR = Pattern.compile("^.*:(.*)!.*$");

	/*
	 * Match group 1 contains the name of the Java package from an OSGi resolution
	 * error message.  If present, match group 2 will be the version constraint.
	 * 
	 * e.g. for the requirement
	 *   (&(osgi.wiring.package=x.y.z)(version>=1.2.3))
	 * 
	 * PACKAGE_NAME_EXTRACTOR will match with group 1 "x.y.z" and group 2 "(version>=1.2.3)". 
	 * 
	 */
	private static Pattern PACKAGE_NAME_EXTRACTOR =
		Pattern.compile("\\(osgi\\.wiring\\.package=([^)]*)\\)(\\(version[^)]*\\))?");

	/**
	 * The syntax of the error generated when OSGi requirements cannot be resolved is
	 * difficult to parse, so we try to extract package name and versions. 
	 * 
	 * @param osgiExceptionMessage the exception message
	 * @return a list of package names, possibly including versions
	 */
	static List<String> extractPackageNamesFromFailedResolution(String osgiExceptionMessage) {
		try (Scanner s = new Scanner(osgiExceptionMessage)) {
			return s.findAll(PACKAGE_NAME_EXTRACTOR).map(m -> {
				if (m.group(2) != null) {
					return m.group(1) + " " + m.group(2);
				}
				return m.group(1);
			}).collect(Collectors.toList());
		}
	}

	static String getEventTypeString(BundleEvent e) {
		switch (e.getType()) {
			case BundleEvent.INSTALLED:
				return "INSTALLED";
			case BundleEvent.RESOLVED:
				return "RESOLVED";
			case BundleEvent.LAZY_ACTIVATION:
				return "LAZY_ACTIVATION";
			case BundleEvent.STARTING:
				return "STARTING";
			case BundleEvent.STARTED:
				return "STARTED";
			case BundleEvent.STOPPING:
				return "STOPPING";
			case BundleEvent.STOPPED:
				return "STOPPED";
			case BundleEvent.UPDATED:
				return "UPDATED";
			case BundleEvent.UNRESOLVED:
				return "UNRESOLVED";
			case BundleEvent.UNINSTALLED:
				return "UNINSTALLED";
			default:
				return "???";
		}
	}

	static String getStateString(Bundle bundle) {
		switch (bundle.getState()) {
			case Bundle.UNINSTALLED:
				return "UNINSTALLED";
			case Bundle.INSTALLED:
				return "INSTALLED";
			case Bundle.RESOLVED:
				return "RESOLVED";
			case Bundle.STARTING:
				return "STARTING";
			case Bundle.STOPPING:
				return "STOPPING";
			case Bundle.ACTIVE:
				return "ACTIVE";
			default:
				return "unknown state";
		}
	}

	/**
	 * parse Import-Package string from a bundle manifest
	 * 
	 * @param importPackageString Import-Package value
	 * @return deduced requirements or null if there was an error
	 * @throws BundleException on parse failure
	 */
	static List<BundleRequirement> parseImportPackage(String importPackageString)
			throws BundleException {
		Map<String, Object> headerMap = new HashMap<>();
		// assume version 2 for a more robust parse
		headerMap.put(Constants.BUNDLE_MANIFESTVERSION, "2");
		// symbolic name is required for version 2 bundle manifest
		headerMap.put(Constants.BUNDLE_SYMBOLICNAME, Constants.SYSTEM_BUNDLE_SYMBOLICNAME);
		headerMap.put(Constants.IMPORT_PACKAGE, importPackageString);
		ManifestParser manifestParser = new ManifestParser(null, null, null, headerMap);
		return manifestParser.getRequirements();
	}

	/**
	 * parse Export-Package string from a bundle manifest
	 * 
	 * @param exportPackageString Import-Package value
	 * @return deduced capabilities or null if there was an error
	 * @throws BundleException on parse failure
	 */
	static List<BundleCapability> parseExportPackage(String exportPackageString)
			throws BundleException {
		Map<String, Object> headerMap = new HashMap<>();
		// assume version 2 for a more robust parse 
		headerMap.put(Constants.BUNDLE_MANIFESTVERSION, "2");
		// symbolic name is required for version 2 bundle manifest
		headerMap.put(Constants.BUNDLE_SYMBOLICNAME, Constants.SYSTEM_BUNDLE_SYMBOLICNAME);
		headerMap.put(Constants.EXPORT_PACKAGE, exportPackageString);
		ManifestParser manifestParser = new ManifestParser(null, null, null, headerMap);
		return manifestParser.getCapabilities();
	}

	// from https://dzone.com/articles/locate-jar-classpath-given
	static String findJarForClass(Class<?> c) {
		URL location;
		String classLocation = c.getName().replace('.', '/') + ".class";
		ClassLoader loader = c.getClassLoader();
		if (loader == null) {
			location = ClassLoader.getSystemResource(classLocation);
		}
		else {
			location = loader.getResource(classLocation);
		}
		if (location != null) {
			Matcher matcher = JAR_FILENAME_EXTRACTOR.matcher(location.toString());
			if (matcher.find()) {
				return matcher.group(1);
			}
			return null; // not loaded from jar?
		}
		return null;
	}

	static void getPackagesFromClasspath(Set<String> s) {
		getClasspathElements().forEach(p -> {
			if (Files.isDirectory(p)) {
				collectPackagesFromDirectory(p, s);
			}
			else if (p.toString().endsWith(".jar")) {
				collectPackagesFromJar(p, s);
			}
		});
	}

	static Stream<Path> getClasspathElements() {
		String classpathStr = System.getProperty("java.class.path");
		return Collections.list(new StringTokenizer(classpathStr, File.pathSeparator))
				.stream()
				.map(String.class::cast)
				.map(Paths::get)
				.map(Path::normalize);
	}

	static void collectPackagesFromDirectory(Path dirPath, Set<String> packages) {
		try (Stream<Path> walk = Files.walk(dirPath)) {
			walk.filter(p -> p.toString().endsWith(".class")).forEach(path -> {
				String relativePath = dirPath.relativize(path).toString();
				int lastSlash = relativePath.lastIndexOf(File.separatorChar);
				packages.add(lastSlash > 0
						? relativePath.substring(0, lastSlash).replace(File.separatorChar, '.')
						: "");
			});
		}
		catch (IOException e) {
			Msg.error(OSGiUtils.class, "Error while collecting packages from directory", e);
		}
	}

	static private boolean hasEvenQuoteCount(String s) {
		return s.chars().filter(c -> c == '"').count() % 2 == 0;
	}

	static void collectPackagesFromJar(Path jarPath, Set<String> packages) {
		try {
			try (JarFile jarFile = new JarFile(jarPath.toFile())) {
				Manifest manifest = jarFile.getManifest();

				// if this jar is an OSGi bundle, use its declared exports
				String exportPackageString = manifest != null
						? manifest.getMainAttributes().getValue(Constants.EXPORT_PACKAGE)
						: null;
				if (exportPackageString != null) {
					String saved = null;
					/*
					 *	split on commas not contained in quotes.
					 * 
					 *	e.g.
					 *		org.foo,org.bar;uses="org.baz,org.qux"
					 *		       ^- should split here  ^- not here
					 *
					 *	We first split on all commas. The first entry, 
					 *		org.foo    
					 *	has an even number of quotes, so it's added as is to packages.
					 *	The second entry,
					 *		        org.bar;uses="org.baz
					 *	has an odd number of quotes, so we save
					 *		        org.bar;uses="org.baz,
					 *	Then the third entry,
					 *		                              org.qux"
					 *	is appended, and the result has an even number of quotes, so is added.
					 */

					for (String packageName : exportPackageString.split(",")) {
						boolean evenQuoteCount = hasEvenQuoteCount(packageName);
						if (saved != null) {
							packageName = saved + packageName;
							evenQuoteCount = !evenQuoteCount;
							saved = null;
						}
						if (evenQuoteCount) {
							packages.add(packageName);
						}
						else {
							saved = packageName + ',';
						}
					}
				}
				else {
					jarFile.stream()
							.filter(entry -> entry.getName().endsWith(".class"))
							.forEach(jarEntry -> {
								String entryName = jarEntry.getName();
								int lastSlash = entryName.lastIndexOf('/');
								if (lastSlash > 0) {
									packages.add(
										entryName.substring(0, lastSlash).replace('/', '.'));
								}
							});
				}
			}
		}
		catch (IOException e) {
			Msg.error(OSGiUtils.class, "Error while collecting packages from jar", e);
		}
	}

}
