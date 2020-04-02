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

import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.*;
import java.util.*;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.tools.*;
import javax.tools.JavaFileObject.Kind;

import org.osgi.framework.Constants;
import org.osgi.framework.wiring.BundleRequirement;
import org.osgi.framework.wiring.BundleWiring;
import org.phidias.compile.BundleJavaManager;

import aQute.bnd.osgi.*;
import aQute.bnd.osgi.Clazz.QUERY;
import generic.jar.ResourceFile;
import ghidra.app.script.*;

public class BundleCompiler {
	private BundleHost bh;

	static final String GENERATED_ACTIVATOR_CLASSNAME = "GeneratedActivator";

	BundleCompiler(BundleHost bh) {
		this.bh = bh;
	}

	private JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();

	/**
	 *  compile a source directory to an exploded bundle
	 *  
	 * @param sb the bundle info to build
	 * @param writer for updating the user during compilation
	 * @throws IOException for source/manifest file reading/generation and binary deletion/creation
	 * @throws OSGiException if generation of bundle metadata fails
	 */
	void compileToExplodedBundle(GhidraSourceBundle sb, PrintWriter writer)
			throws IOException, OSGiException {

		sb.compileAttempted();
		sb.setSummary(String.format("build %d files, skipping %d%s", sb.getNewSourcesCount(),
			sb.getFailingSourcesCount(), sb.newManifestFile() ? ", new manifest" : ""));

		ResourceFile srcdir = sb.getSourceDir();
		Path bindir = sb.getBinDir();
		Files.createDirectories(bindir);

		List<String> options = new ArrayList<>();
		options.add("-g");
		options.add("-d");
		options.add(bindir.toString());
		options.add("-sourcepath");
		options.add(srcdir.toString());
		options.add("-classpath");
		options.add(System.getProperty("java.class.path") + File.pathSeparator + bindir.toString());
		options.add("-proc:none");

		final JavaFileManager rfm =
			new ResourceFileJavaFileManager(Collections.singletonList(sb.getSourceDir()));

		BundleJavaManager bjm = new BundleJavaManager(bh.getHostFramework(), rfm, options);
		// The phidias BundleJavaManager is for compiling from within a bundle -- it makes the
		// bundle dependencies available to the compiler classpath.  Here, we are compiling in an as-yet 
		// non-existing bundle, so we forge the wiring based on @imports metadata.

		// XXX skip this if there's a source manifest, emit warnings about @imports
		// get wires for currently active bundles to satisfy all requirements
		List<BundleRequirement> reqs = sb.getAllReqs();
		List<BundleWiring> bundleWirings = bh.resolve(reqs);

		if (!reqs.isEmpty()) {
			writer.printf("%d import requirement%s remain%s unresolved:\n", reqs.size(),
				reqs.size() > 1 ? "s" : "", reqs.size() > 1 ? "" : "s");
			for (BundleRequirement req : reqs) {
				writer.printf("  %s\n", req.toString());
			}

			sb.setSummary(
				String.format("%d missing @import%s:", reqs.size(), reqs.size() > 1 ? "s" : "",
					reqs.stream().flatMap(
						r -> OSGiUtils.extractPackages(r.toString()).stream()).distinct().collect(
							Collectors.joining(","))));
		}
		else {
			sb.setSummary("");
		}
		// XXX add sources that will fail to call attention
		List<ResourceFile> newSource = sb.getNewSources();
		for (BundleRequirement req : reqs) {
			newSource.addAll(sb.req2file.get(req.toString()));
		}

		// send the capabilities to phidias
		bundleWirings.forEach(bjm::addBundleWiring);

		final List<ResourceFileJavaFileObject> sourceFiles = newSource.stream().map(
			sf -> new ResourceFileJavaFileObject(sf.getParentFile(), sf, Kind.SOURCE)).collect(
				Collectors.toList());

		Path dmf = bindir.resolve("META-INF").resolve("MANIFEST.MF");
		if (Files.exists(dmf)) {
			Files.delete(dmf);
		}

		// try to compile, if we fail, avoid offenders and try again
		while (!sourceFiles.isEmpty()) {
			DiagnosticCollector<JavaFileObject> diagnostics =
				new DiagnosticCollector<JavaFileObject>();
			JavaCompiler.CompilationTask task =
				compiler.getTask(writer, bjm, diagnostics, options, null, sourceFiles);
			// task.setProcessors // for annotation processing / code generation

			Boolean successfulCompilation = task.call();
			if (successfulCompilation) {
				break;
			}
			for (Diagnostic<? extends JavaFileObject> d : diagnostics.getDiagnostics()) {
				String err = d.toString() + "\n";
				writer.write(err);
				ResourceFileJavaFileObject sf = (ResourceFileJavaFileObject) d.getSource();
				ResourceFile rf = sf.getFile();
				sb.buildError(rf, err); // remember all errors for this file
				if (sourceFiles.remove(sf)) {
					writer.printf("skipping %s\n", sf.toString());
					// if it's a script, mark it for having compile errors
					if (GhidraScriptUtil.containsMetadata(rf)) {
						ScriptInfo info = GhidraScriptUtil.getScriptInfo(rf);
						info.setCompileErrors(true);
					}
				}
			}
		}
		// mark the successful compilations
		for (ResourceFileJavaFileObject sf : sourceFiles) {
			ResourceFile rf = sf.getFile();
			if (GhidraScriptUtil.containsMetadata(rf)) {
				ScriptInfo info = GhidraScriptUtil.getScriptInfo(rf);
				info.setCompileErrors(false);
			}
		}
		// buildErrors is now up to date, set status
		if (sb.getFailingSourcesCount() > 0) {
			sb.appendSummary(String.format("%d failing source files", sb.getFailingSourcesCount()));
		}

		ResourceFile smf = new ResourceFile(srcdir, "META-INF" + File.separator + "MANIFEST.MF");
		if (smf.exists()) {
			System.err.printf("Found manifest, not generating one\n");
			Files.createFile(dmf);
			Files.copy(smf.getInputStream(), dmf, StandardCopyOption.REPLACE_EXISTING);
			return;
		}

		// no manifest, so create one with bndtools
		Analyzer analyzer = new Analyzer();
		analyzer.setJar(new Jar(bindir.toFile())); // give bnd the contents
		Stream<Object> bjars = Files.list(GhidraScriptUtil.getCompiledBundlesDir()).filter(
			f -> f.toString().endsWith(".jar")).map(f -> {
				try {
					return new Jar(f.toFile());
				}
				catch (IOException e1) {
					e1.printStackTrace(writer);
					return null;
				}
			});

		analyzer.addClasspath(bjars.collect(Collectors.toUnmodifiableList()));
		analyzer.setProperty("Bundle-SymbolicName",
			BundleHost.getSymbolicNameFromSourceDir(srcdir));
		analyzer.setProperty("Bundle-Version", "1.0");
		analyzer.setProperty("Import-Package", "*");
		analyzer.setProperty("Export-Package", "!*.private.*,!*.internal.*,*");
		// analyzer.setBundleActivator(s);

		try {
			Manifest manifest;
			try {
				manifest = analyzer.calcManifest();
			}
			catch (Exception e) {
				sb.appendSummary("bad manifest");
				throw new OSGiException("failed to calculate manifest by analyzing code", e);
			}
			Attributes ma = manifest.getMainAttributes();

			String activator_classname = null;
			try {
				for (Clazz clazz : analyzer.getClassspace().values()) {
					if (clazz.is(QUERY.IMPLEMENTS,
						new Instruction("org.osgi.framework.BundleActivator"), analyzer)) {
						System.err.printf("found BundleActivator class %s\n", clazz);
						activator_classname = clazz.toString();
					}
				}
			}
			catch (Exception e) {
				sb.appendSummary("failed bnd analysis");
				throw new OSGiException("failed to query classes while searching for activator", e);
			}
			if (activator_classname == null) {
				activator_classname = GENERATED_ACTIVATOR_CLASSNAME;
				if (!buildDefaultActivator(bindir, activator_classname, writer)) {
					sb.appendSummary("failed to build generated activator");
					return;
				}
				// since we add the activator after bndtools built the imports, we should add its imports too
				String imps = ma.getValue(Constants.IMPORT_PACKAGE);
				if (imps == null) {
					ma.putValue(Constants.IMPORT_PACKAGE,
						GhidraBundleActivator.class.getPackageName());
				}
				else {
					ma.putValue(Constants.IMPORT_PACKAGE,
						imps + "," + GhidraBundleActivator.class.getPackageName());
				}
			}
			ma.putValue(Constants.BUNDLE_ACTIVATOR, activator_classname);

			// write the manifest
			Files.createDirectories(dmf.getParent());
			try (OutputStream out = Files.newOutputStream(dmf)) {
				manifest.write(out);
			}
		}
		finally {
			analyzer.close();
		}
	}

	/**
	 * create and compile a default bundle activator
	 * 
	 * @param bindir destination for class file
	 * @param activator_classname the name to use for the genearted activator class
	 * @param writer for writing compile errors
	 * @return true if compilation succeeded
	 * @throws IOException for failed write of source/binary activator
	 */
	private boolean buildDefaultActivator(Path bindir, String activator_classname, Writer writer)
			throws IOException {
		Path activator_dest = bindir.resolve(activator_classname + ".java");

		try (PrintWriter out =
			new PrintWriter(Files.newBufferedWriter(activator_dest, Charset.forName("UTF-8")))) {
			out.println("import " + GhidraBundleActivator.class.getName() + ";");
			out.println("import org.osgi.framework.BundleActivator;");
			out.println("import org.osgi.framework.BundleContext;");
			out.println("public class " + GENERATED_ACTIVATOR_CLASSNAME +
				" extends GhidraBundleActivator {");
			out.println("  protected void start(BundleContext bc, Object api) {");
			out.println("    // TODO: stuff to do on bundle start");
			out.println("  }");
			out.println("  protected void stop(BundleContext bc, Object api) {");
			out.println("    // TODO: stuff to do on bundle stop");
			out.println("  }");
			out.println();
			out.println("}");
		}

		List<String> options = new ArrayList<>();
		options.add("-g");
		options.add("-d");
		options.add(bindir.toString());
		options.add("-sourcepath");
		options.add(bindir.toString());
		options.add("-classpath");
		options.add(System.getProperty("java.class.path"));
		options.add("-proc:none");

		StandardJavaFileManager fm = compiler.getStandardFileManager(null, null, null);
		BundleJavaManager bjm = new BundleJavaManager(bh.getHostFramework(), fm, options);
		Iterable<? extends JavaFileObject> sourceFiles =
			fm.getJavaFileObjectsFromPaths(List.of(activator_dest));
		DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<JavaFileObject>();
		JavaCompiler.CompilationTask task =
			compiler.getTask(writer, bjm, diagnostics, options, null, sourceFiles);
		if (!task.call()) {
			for (Diagnostic<? extends JavaFileObject> d : diagnostics.getDiagnostics()) {
				writer.write(d.getSource().toString() + ": " + d.getMessage(null) + "\n");
			}
			return false;
		}
		return true;
	}

}
