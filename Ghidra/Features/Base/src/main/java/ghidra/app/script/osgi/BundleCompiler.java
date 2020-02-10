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

package ghidra.app.script.osgi;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.tools.*;
import javax.tools.JavaFileObject.Kind;

import org.phidias.compile.BundleJavaManager;

import aQute.bnd.osgi.*;
import aQute.bnd.osgi.Clazz.QUERY;
import generic.jar.ResourceFile;
import ghidra.app.script.*;

public class BundleCompiler {

	private BundleHost bh;

	public BundleCompiler(BundleHost bh) {
		this.bh = bh;
	}

	/** compile a source directory to an exploded bundle */
	public void compileToExplodedBundle(ResourceFile srcdir, Path bindir, Writer output)
			throws IOException {
		JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
		List<String> options = new ArrayList<>();
		options.add("-g");
		options.add("-d");
		options.add(bindir.toString());
		options.add("-sourcepath");
		options.add(srcdir.toString());
		options.add("-classpath");
		options.add(System.getProperty("java.class.path") + File.pathSeparator + bindir.toString());
		options.add("-proc:none");
		final JavaFileManager fm0 =
			new ResourceFileJavaFileManager(GhidraScriptUtil.getScriptSourceDirectories());
		BundleJavaManager fm = new BundleJavaManager(bh.getHostFramework(), fm0, options);
		DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<JavaFileObject>();

		final List<ResourceFileJavaFileObject> compilationUnits = new ArrayList<>();

		BundleHost.visitUpdatedClassFiles(srcdir, bindir, (sf, bf) -> {
			if (sf != null) {
				compilationUnits.add(
					new ResourceFileJavaFileObject(sf.getParentFile(), sf, Kind.SOURCE));
			}
		});

		Path dmf = bindir.resolve("META-INF").resolve("MANIFEST.MF");
		if (Files.exists(dmf)) {
			Files.delete(dmf);
		}

		JavaCompiler.CompilationTask task =
			compiler.getTask(output, fm, diagnostics, options, null, compilationUnits);
		// task.setProcessors // for annotation processing / code generation

		Boolean successfulCompilation = task.call();
		output.flush();
		System.err.printf("%s: %s\n", successfulCompilation ? "Success" : "Fail", output);

		if (successfulCompilation) {
			ResourceFile smf =
				new ResourceFile(srcdir, "META-INF" + File.separator + "MANIFEST.MF");
			if (smf.exists()) {
				System.err.printf("Found manifest, not generating one\n");
				Files.createFile(dmf);
				Files.copy(smf.getInputStream(), dmf, StandardCopyOption.REPLACE_EXISTING);
				return;
			}

			// no manifest, so create one with bndtools
			Analyzer analyzer = new Analyzer();
			analyzer.setJar(new Jar(bindir.toFile())); // give bnd the contents
			Stream<Object> bjars = Files.list(bh.getCompiledBundlesDir()).filter(
				f -> f.toString().endsWith(".jar")).map(f -> {
					try {
						return new Jar(f.toFile());
					}
					catch (IOException e1) {
						e1.printStackTrace();
						return null;
					}
				});

			analyzer.addClasspath(bjars.collect(Collectors.toUnmodifiableList()));
			analyzer.setProperty("Bundle-SymbolicName",
				JavaScriptProvider.getSymbolicNameFromSourceDir(srcdir));
			analyzer.setProperty("Bundle-Version", "1.0");
			analyzer.setProperty("Import-Package", "*");
			// analyzer.setBundleActivator(s);

			try {
				Manifest manifest = analyzer.calcManifest();
				Attributes ma = manifest.getMainAttributes();

				String activator_classname = null;
				for (Clazz clazz : analyzer.getClassspace().values()) {
					if (clazz.is(QUERY.IMPLEMENTS,
						new Instruction("org.osgi.framework.BundleActivator"), analyzer)) {
						System.err.printf("found BundleActivator class %s\n", clazz);
						activator_classname = clazz.toString();
					}
				}
				if (activator_classname == null) {
					Path activator_dest = bindir.resolve("GeneratedActivator.java");
					try (PrintWriter writer = new PrintWriter(
						Files.newBufferedWriter(activator_dest, Charset.forName("UTF-8")))) {
						writer.println("import ghidra.app.script.osgi.GhidraBundleActivator;");
						writer.println("import org.osgi.framework.BundleActivator;");
						writer.println("import org.osgi.framework.BundleContext;");
						writer.println(
							"public class GeneratedActivator extends GhidraBundleActivator {");
						writer.println("  protected void start(BundleContext bc, Object api) {");
						writer.println("    // TODO: stuff to do on bundle start");
						writer.println("  }");
						writer.println("  protected void stop(BundleContext bc, Object api) {");
						writer.println("    // TODO: stuff to do on bundle stop");
						writer.println("  }");
						writer.println();
						writer.println("}");
					}
					catch (IOException ex) {
						ex.printStackTrace();
						return;
					}
					activator_classname = "GeneratedActivator";

					options.clear();
					options.add("-g");
					options.add("-d");
					options.add(bindir.toString());
					options.add("-sourcepath");
					options.add(bindir.toString());
					options.add("-classpath");
					options.add(System.getProperty("java.class.path"));
					options.add("-proc:none");

					StandardJavaFileManager fm02 =
						compiler.getStandardFileManager(null, null, null);
					fm = new BundleJavaManager(bh.getHostFramework(), fm02, options);
					Iterable<? extends JavaFileObject> compilationUnits2 =
						fm02.getJavaFileObjectsFromPaths(List.of(activator_dest));

					JavaCompiler.CompilationTask task2 =
						compiler.getTask(output, fm, diagnostics, options, null, compilationUnits2);
					if (!task2.call()) {
						return;
					}
					// since we add the activator after bndtools built the imports, we should add its imports too
					String imps = ma.getValue(Constants.IMPORT_PACKAGE);
					ma.putValue(Constants.IMPORT_PACKAGE, imps + ",ghidra.app.script.osgi");
				}
				ma.putValue(Constants.BUNDLE_ACTIVATOR, activator_classname);

				Files.createDirectories(dmf.getParent());
				try (OutputStream out = Files.newOutputStream(dmf)) {
					manifest.write(out);
				}
			}
			catch (Exception e) {
				e.printStackTrace();
			}
			analyzer.close();
		}
		else {
			for (Diagnostic<? extends JavaFileObject> dm : diagnostics.getDiagnostics()) {
				System.err.printf("COMPILE ERROR: %s\n", dm);
			}
		}
	}

}
