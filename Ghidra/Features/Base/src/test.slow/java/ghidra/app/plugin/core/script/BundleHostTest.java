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
package ghidra.app.plugin.core.script;

import static org.junit.Assert.*;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.*;
import org.osgi.framework.Bundle;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.osgi.*;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import utilities.util.FileUtilities;

public class BundleHostTest extends AbstractGhidraHeadlessIntegrationTest {
	private static final String TEMP_NAME_PREFIX = "sourcebundle";

	// the version of Guava Ghidra is currently using.
	private static final int GUAVA_MAJOR_VERSION = 19;

	private BundleHost bundleHost;
	private CapturingBundleHostListener capturingBundleHostListener;

	private Set<Path> tempDirs = new HashSet<>();
	private LinkedList<GhidraBundle> bundleStack = new LinkedList<>();
	private GhidraBundle currentBundle;

	private static void wipe(Path path) {
		FileUtilities.deleteDir(path);
	}

	private GhidraBundle pushNewBundle() throws IOException {
		String dir = String.format(TEMP_NAME_PREFIX + "%03d", tempDirs.size());
		Path tmpDir = new File(getTestDirectoryPath(), dir).toPath();
		Files.createDirectories(tmpDir);
		tempDirs.add(tmpDir);

		ResourceFile sourceDirectory = new ResourceFile(tmpDir.toFile());
		currentBundle = bundleHost.add(sourceDirectory, true, false);
		bundleStack.push(currentBundle);
		return currentBundle;
	}

	private static class CapturingBundleHostListener implements BundleHostListener {
		String lastBuildSummary;

		@Override
		public void bundleBuilt(GhidraBundle gbundle, String summary) {
			if (summary != null) {
				this.lastBuildSummary = summary;
			}
		}
	}

	@Before
	public void setup() throws OSGiException, IOException {
		wipe(GhidraSourceBundle.getCompiledBundlesDir());
		deleteSimilarTempFiles(TEMP_NAME_PREFIX);

		bundleHost = new BundleHost();
		bundleHost.startFramework();
		capturingBundleHostListener = new CapturingBundleHostListener();
		bundleHost.addListener(capturingBundleHostListener);

		pushNewBundle();
	}

	@After
	public void tearDown() {
		bundleHost.dispose();
		capturingBundleHostListener = null;
		bundleHost = null;

		for (Path tmpdir : tempDirs) {
			wipe(tmpdir);
		}
	}

	private void buildWithExpectations(String expectedCompilerOutput, String expectedSummary)
			throws Exception {
		StringWriter stringWriter = new StringWriter();

		currentBundle.build(new PrintWriter(stringWriter));
		stringWriter.flush();

		assertEquals("unexpected output during build", expectedCompilerOutput,
			stringWriter.getBuffer().toString());

		assertEquals("wrong summary", expectedSummary,
			capturingBundleHostListener.lastBuildSummary);
	}

	private void activate() throws Exception {
		Bundle bundle = bundleHost.install(currentBundle);
		assertNotNull("failed to install bundle", bundle);
		bundle.start();
	}

	private void buildAndActivate() throws Exception {
		buildWithExpectations("", "");
		activate();
	}

	private Class<?> loadClass(String classname) throws ClassNotFoundException {
		Class<?> clazz = currentBundle.getOSGiBundle().loadClass(classname);
		assertNotNull("failed to load class", clazz);
		return clazz;
	}

	private void addClass(String fullclassname, String body) throws IOException {
		addClass("", fullclassname, body);
	}

	private void addClass(String imports, String fullclassname, String body) throws IOException {
		addClass("", imports, fullclassname, body);
	}

	private void addClass(String meta, String imports, String fullclassname, String body)
			throws IOException {
		String simplename;
		Path tmpsource = currentBundle.getFile().getFile(false).toPath();

		if (fullclassname.contains(".")) {
			String packagename;

			Pattern pattern = Pattern.compile("^(.*)\\.([^.]*)$");
			Matcher matcher = pattern.matcher(fullclassname);
			if (!matcher.matches()) {
				throw new IllegalArgumentException(
					"fullclassname must be of the form \"xxxx.xxxx.Xxxx\"");
			}
			packagename = matcher.group(1);
			simplename = matcher.group(2);

			for (String n : packagename.split("\\.")) {
				tmpsource = tmpsource.resolve(n);
			}
			Files.createDirectories(tmpsource);
			tmpsource = tmpsource.resolve(simplename + ".java");

			Files.writeString(tmpsource,
				String.format("%s\npackage %s;\n%s\npublic class %s {\n%s\n}\n", meta, packagename,
					imports, simplename, body));
		}
		else {
			simplename = fullclassname;
			tmpsource = tmpsource.resolve(simplename + ".java");
			Files.writeString(tmpsource, String.format("%s\n%s\npublic class %s {\n%s\n}\n", meta,
				imports, simplename, body));

		}

	}

	private Object getInstance(String classname) throws Exception {
		Class<?> clazz = loadClass(classname);
		Object object = clazz.getDeclaredConstructor().newInstance();
		assertNotNull("failed to create instance", object);
		return object;
	}

	/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

	@Test
	public void testSimpleBuildAndLoadclass() throws Exception {
		// @formatter:off
		addClass(
			"apackage.AClass", 
			"@Override\n" + 
			"public String toString() {\n" + 
			"	return \"yupyup\";\n" + 
			"}\n" 
		);
		// @formatter:on

		buildAndActivate();

		assertEquals("wrong response from instantiated class", "yupyup",
			getInstance("apackage.AClass").toString());
	}

	@Test
	public void testCompileWhatYouCan() throws Exception {
		// @formatter:off
		addClass(
			"apackage.AClass", 
			"@Override\n" + 
			"public String toString() {\n" + 
			"	return \"yupyup\";\n" + 
			"}\n" 
		);

		addClass(
			"apackage.BClass", 
			"@Override\n" + 
			"public String toString() {\n" +
			"   failing java goes here\n" +
			"	return \"yupyup\";\n" + 
			"}\n" 
		);

		buildWithExpectations(
			"BClass.java:7: error: ';' expected\n" + 
			"   failing java goes here\n" + 
			"               ^\n" + 
			"BClass.java:7: error: ';' expected\n" + 
			"   failing java goes here\n" + 
			"                         ^\n" + 
			"skipping "+currentBundle.getFile().toString()+File.separator+"apackage"+File.separator+"BClass.java\n"
			,
			"1 source file with errors"
		); 
		// @formatter:on

		activate();

		assertEquals("wrong response from instantiated class", "yupyup",
			getInstance("apackage.AClass").toString());
	}

	@Test
	public void testLibraryInBundle() throws Exception {
		// @formatter:off
		addClass(
			"lib.Library", 
			"public static String sup() {\n" + 
			"	return \"yupyup\";\n" + 
			"}\n" 
		);
		addClass(
			"import lib.Library;\n",
			"apackage.AClass", 
			"@Override\n" + 
			"public String toString() {\n" + 
			"	return \"lib says \" + Library.sup();\n" + 
			"}\n"
		);
		// @formatter:on
		buildAndActivate();
		assertEquals("wrong response from instantiated class", "lib says yupyup",
			getInstance("apackage.AClass").toString());
	}

	@Test
	public void testCantLoadLibraryFromOtherBundle() throws Exception {
		// @formatter:off
		addClass(
			"lib.Library", 
			"public static String sup() {\n" + 
			"	return \"yupyup\";\n" + 
			"}\n" 
		);
		buildAndActivate();
		Class<?> libclass = loadClass("lib.Library");
		assertEquals("wrong response from loaded class", "yupyup",
			libclass.getMethod("sup").invoke(null).toString());

		
		pushNewBundle();
		addClass(
			"import lib.Library;\n",
			"apackage.AClass", 
			"@Override\n" + 
			"public String toString() {\n" + 
			"	return \"lib says \" + Library.sup();\n" + 
			"}\n"
		);

		buildWithExpectations(
			"AClass.java:3: error: package lib does not exist\n" + 
			"import lib.Library;\n" + 
			"          ^\n" + 
			"AClass.java:8: error: cannot find symbol\n" + 
			"	return \"lib says \" + Library.sup();\n" + 
			"	                     ^\n" + 
			"  symbol:   variable Library\n" + 
			"  location: class apackage.AClass\n" +
			"skipping "+currentBundle.getFile().toString()+File.separator+"apackage"+File.separator+"AClass.java\n"
			,
			"1 source file with errors"
		);
		// @formatter:on
	}

	@Test
	public void testLoadLibraryFromOtherBundleWithImportsTag() throws Exception {
		// @formatter:off
		addClass(
			"lib.Library", 
			"public static String sup() {\n" + 
			"	return \"yupyup\";\n" + 
			"}\n" 
		);
		buildAndActivate();
		Class<?> libclass = loadClass("lib.Library");
		assertEquals("wrong response from loaded class", "yupyup",
			libclass.getMethod("sup").invoke(null).toString());

		
		pushNewBundle();
		// @importpackage tag is only parsed from classes in default package
		addClass(
			"//@importpackage lib\n"
			,
			"import lib.Library;\n"
			,
			"AClass", 
			"@Override\n" + 
			"public String toString() {\n" + 
			"	return \"lib says \" + Library.sup();\n" + 
			"}\n"
		);

		buildAndActivate();
		assertEquals("wrong response from instantiated class", "lib says yupyup",
			getInstance("AClass").toString());
		// @formatter:on
	}

	@Test
	public void testImportFromExtraSystemPackagesWithVersionConstraint() throws Exception {
		// @formatter:off
		String goodRange = String.format("[%d,%d)", GUAVA_MAJOR_VERSION, GUAVA_MAJOR_VERSION+1);
		addClass(
			"//@importpackage com.google.common.io;version=\""+goodRange+"\"\n",
			"import com.google.common.io.BaseEncoding;",
			"AClass", 
			"@Override\n" + 
			"public String toString() {\n" + 
			"	return BaseEncoding.base16().encode(new byte[] {0x42});\n" + 
			"}\n"
		);

		buildAndActivate();
		assertEquals("wrong response from instantiated class", "42",
			getInstance("AClass").toString());
		// @formatter:on
	}

	@Test
	public void testImportFromExtraSystemPackagesWithBadVersionConstraint() throws Exception {
		// @formatter:off
		String badRange = String.format("[%d,%d)", GUAVA_MAJOR_VERSION+1, GUAVA_MAJOR_VERSION+2);
		addClass(
			"//@importpackage com.google.common.io;version=\""+badRange+"\"\n",
			"import com.google.common.io.BaseEncoding;",
			"AClass", 
			"@Override\n" + 
			"public String toString() {\n" + 
			"	return BaseEncoding.base16().encode(new byte[] {0x42});\n" + 
			"}\n"
		);

		buildWithExpectations(
			"1 import requirement remains unresolved:\n" + 
			"  [null] osgi.wiring.package; (&(osgi.wiring.package=com.google.common.io)" +
			  "(version>="+(GUAVA_MAJOR_VERSION+1)+".0.0)" +
			  "(!(version>="+(GUAVA_MAJOR_VERSION+2)+".0.0))), " +
			  "from "+generic.util.Path.toPathString(currentBundle.getFile())+"/AClass.java\n",
			"1 missing package import:com.google.common.io (version>="+(GUAVA_MAJOR_VERSION+1)+".0.0)" +
			  ", 1 source file with errors"
		);
		// @formatter:on
	}

	@Test
	public void testLoadLibraryFromOtherBundleWithManifest() throws Exception {
		// @formatter:off
		addClass(
			"lib.Library", 
			"public static String sup() {\n" + 
			"	return \"yupyup\";\n" + 
			"}\n" 
		);
		buildAndActivate();
		
		pushNewBundle();
		addClass(
			"import lib.Library;\n",
			"apackage.AClass", 
			"@Override\n" + 
			"public String toString() {\n" + 
			"	return \"lib says \" + Library.sup();\n" + 
			"}\n"
		);
		
		Path path = currentBundle.getFile().getFile(false).toPath();
		path=path.resolve("META-INF");
		Files.createDirectories(path);
		Path manifest=path.resolve("MANIFEST.MF");
		
		Files.writeString(manifest,
			"Manifest-Version: 1.0\n" + 
			"Bundle-ManifestVersion: 2\n" + 
			"Import-Package: lib\n" + 
			"Require-Capability: osgi.ee;filter:=\"(&(osgi.ee=JavaSE)(version=11))\"\n" + 
			"Bundle-SymbolicName: ghidratesting.bundleX\n" + 
			"Bundle-Version: 1.0\n" + 
			"Bundle-Name: bundlex\n" 
		);

		buildAndActivate();
		// @formatter:on
		assertEquals("wrong response from instantiated class", "lib says yupyup",
			getInstance("apackage.AClass").toString());

	}

}
