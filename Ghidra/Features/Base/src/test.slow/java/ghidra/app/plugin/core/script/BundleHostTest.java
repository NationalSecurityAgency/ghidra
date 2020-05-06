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

public class BundleHostTest extends AbstractGhidraHeadlessIntegrationTest {
	static protected void wipe(Path path) throws IOException {
		if (Files.exists(path)) {
			for (Path p : (Iterable<Path>) Files.walk(path).sorted(
				Comparator.reverseOrder())::iterator) {
				Files.deleteIfExists(p);
			}
		}
	}

	BundleHost bundleHost;
	CapturingBundleHostListener bhl;

	Set<Path> tmpdirs = new HashSet<>();
	LinkedList<GhidraBundle> gbstack = new LinkedList<>();
	GhidraBundle current_gb;

	protected GhidraBundle pushNewBundle() throws IOException {
		String dir = String.format("sourcebundle%03d", tmpdirs.size());
		Path tmpDir = new File(getTestDirectoryPath(), dir).toPath();
		Files.createDirectories(tmpDir);
		tmpdirs.add(tmpDir);

		ResourceFile rp = new ResourceFile(tmpDir.toFile());
		current_gb = bundleHost.addGhidraBundle(rp, true, false);
		gbstack.push(current_gb);
		return current_gb;
	}

	static class CapturingBundleHostListener implements BundleHostListener {
		String lastBuildSummary;

		@Override
		public void bundleBuilt(GhidraBundle gbundle, String summary) {
			this.lastBuildSummary = summary;
		}
	}

	@Before
	public void setup() throws OSGiException, IOException {
		wipe(BundleHost.getCompiledBundlesDir());

		bundleHost = new BundleHost();
		bundleHost.startFramework();
		bhl = new CapturingBundleHostListener();
		bundleHost.addListener(bhl);

		pushNewBundle();
	}

	@After
	public void tearDown() throws IOException {
		bundleHost.dispose();
		bhl = null;
		bundleHost = null;

		for (Path tmpdir : tmpdirs) {
			wipe(tmpdir);
		}
	}

	protected void buildWithExpectations(String expectedCompilerOutput, String expectedSummary)
			throws Exception {
		StringWriter sw = new StringWriter();

		current_gb.build(new PrintWriter(sw));
		sw.flush();

		assertEquals("unexpected output during build", expectedCompilerOutput,
			sw.getBuffer().toString());

		assertEquals("wrong summary", expectedSummary, bhl.lastBuildSummary);
	}

	protected void activate() throws Exception {
		Bundle bundle = bundleHost.installFromLoc(current_gb.getBundleLoc());
		assertNotNull("failed to install bundle", bundle);
		bundle.start();
	}

	protected void buildAndActivate() throws Exception {
		buildWithExpectations("", "");
		activate();
	}

	protected Class<?> loadClass(String classname) throws ClassNotFoundException {
		Class<?> clazz = current_gb.getBundle().loadClass(classname);
		assertNotNull("failed to load class", clazz);
		return clazz;
	}

	protected void addClass(String fullclassname, String body) throws IOException {
		addClass("", fullclassname, body);
	}

	protected void addClass(String imports, String fullclassname, String body) throws IOException {
		addClass("", imports, fullclassname, body);
	}

	protected void addClass(String meta, String imports, String fullclassname, String body)
			throws IOException {
		String simplename;
		Path tmpsource = current_gb.getPath().getFile(false).toPath();

		if (fullclassname.contains(".")) {
			String packagename;

			Pattern classpat = Pattern.compile("^(.*)\\.([^.]*)$");
			Matcher m = classpat.matcher(fullclassname);
			if (!m.matches()) {
				throw new IllegalArgumentException(
					"fullclassname must be of the form \"xxxx.xxxx.Xxxx\"");
			}
			packagename = m.group(1);
			simplename = m.group(2);

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

	protected Object getInstance(String classname) throws Exception {
		Class<?> clazz = loadClass(classname);
		Object o = clazz.getDeclaredConstructor().newInstance();
		assertNotNull("failed to create instance", o);
		return o;
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
			String.format("skipping %s/apackage/BClass.java\n", current_gb.getPath().toString())
			,
			"1 failing source files"
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
			String.format("skipping %s/apackage/AClass.java\n", current_gb.getPath().toString())
			,
			"1 failing source files"
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
		// @imports tag is only parsed from classes in default package
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
		
		Path p = current_gb.getPath().getFile(false).toPath();
		p=p.resolve("META-INF");
		Files.createDirectories(p);
		Path manifest=p.resolve("MANIFEST.MF");
		
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
