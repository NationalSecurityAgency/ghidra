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
import java.util.*;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.tools.*;
import javax.tools.JavaFileObject.Kind;

import org.apache.felix.framework.util.manifestparser.ManifestParser;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleException;
import org.osgi.framework.Constants;
import org.osgi.framework.wiring.*;
import org.phidias.compile.BundleJavaManager;

import aQute.bnd.osgi.*;
import aQute.bnd.osgi.Clazz.QUERY;
import generic.jar.ResourceFile;
import ghidra.app.script.*;
import ghidra.app.script.osgi.BundleHost.SourceBundleInfo;
import ghidra.util.Msg;

public class BundleCompiler {

	private BundleHost bh;

	public BundleCompiler(BundleHost bh) {
		this.bh = bh;
	}

	JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();

	void wireAdditionalBundles(List<ResourceFile> newSource, BundleJavaManager bjm,
			PrintWriter writer) throws IOException {
		// parse metadata for the scripts we're compiling
		List<ScriptInfo> infos = newSource.stream().filter(GhidraScriptUtil::contains).map(
			GhidraScriptUtil::getScriptInfo).collect(Collectors.toList());

		// concatenate all imports into a single "Import-Package" string
		String package_imports = infos.stream().map(ScriptInfo::getImports).filter(
			s -> s != null && !s.isEmpty()).collect(Collectors.joining(","));

		if (package_imports == null || package_imports.isEmpty()) {
			return;
		}

		// parse it with Felix's ManifestParser to a list of BundleRequirement objects
		Map<String, Object> headerMap = new HashMap<>();
		headerMap.put(Constants.IMPORT_PACKAGE, package_imports);
		ManifestParser mp;
		try {
			mp = new ManifestParser(null, null, null, headerMap);
		}
		catch (BundleException e) {
			throw new IOException("failed to parse imports metadata", e);
		}
		List<BundleRequirement> reqs = mp.getRequirements();

		// enumerate active bundles, looking for capabilities meeting our requirements
		List<BundleWiring> bundleWirings = new ArrayList<>();
		for (Bundle b : bh.bc.getBundles()) {
			if (b.getState() == Bundle.ACTIVE) {
				BundleWiring bw = b.adapt(BundleWiring.class);
				boolean keeper = false;
				for (BundleCapability cap : bw.getCapabilities(null)) {
					Iterator<BundleRequirement> it = reqs.iterator();
					while (it.hasNext()) {
						BundleRequirement req = it.next();
						if (req.matches(cap)) {
							it.remove();
							keeper = true;
						}
					}
				}
				if (keeper) {
					bundleWirings.add(bw);
				}
			}
		}

		if (!reqs.isEmpty()) {
			writer.printf("%d import requirement%s remain%s:\n", reqs.size(),
				reqs.size() > 1 ? "s" : "", reqs.size() > 1 ? "" : "s");
			for (BundleRequirement req : reqs) {
				writer.printf("  %s\n", req.toString());
			}
		}

		// finally, add all the wirings we found to bjm
		bundleWirings.forEach(bw -> bjm.addBundleWiring(bw));
	}

	// compile a source directory to an exploded bundle
	public void compileToExplodedBundle(SourceBundleInfo bi, List<ResourceFile> newSource,
			PrintWriter writer) throws IOException {

		ResourceFile srcdir = bi.getSourceDir();
		Path bindir = bi.getBinDir();

		List<String> options = new ArrayList<>();
		options.add("-g");
		options.add("-d");
		options.add(bindir.toString());
		options.add("-sourcepath");
		options.add(srcdir.toString());
		options.add("-classpath");
		options.add(System.getProperty("java.class.path") + File.pathSeparator + bindir.toString());
		options.add("-proc:none");

		// final JavaFileManager rfm = new ResourceFileJavaFileManager(Collections.singletonList(bi.getSourceDir()));
		final JavaFileManager rfm =
			new ResourceFileJavaFileManager(Collections.singletonList(bi.getSourceDir()));

		// phidias provides a JavaFileManager for compiling from within a bundle -- making all of the
		// bundles dependencies available to the compilation.  Here, we are compiling for an as-yet 
		// non-existant bundle, so we forge the wiring based on metadata.
		BundleJavaManager bjm = new BundleJavaManager(bh.getHostFramework(), rfm, options);

		wireAdditionalBundles(newSource, bjm, writer);

		final List<ResourceFileJavaFileObject> compilationUnits = newSource.stream().map(
			sf -> new ResourceFileJavaFileObject(sf.getParentFile(), sf, Kind.SOURCE)).collect(
				Collectors.toList());

		Path dmf = bindir.resolve("META-INF").resolve("MANIFEST.MF");
		if (Files.exists(dmf)) {
			Files.delete(dmf);
		}

		// try to compile, if we fail, avoid offenders and try again
		while (!compilationUnits.isEmpty()) {
			DiagnosticCollector<JavaFileObject> diagnostics =
				new DiagnosticCollector<JavaFileObject>();
			JavaCompiler.CompilationTask task =
				compiler.getTask(writer, bjm, diagnostics, options, null, compilationUnits);
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
				bi.buildError(rf, err); // remember all errors for this file
				if (compilationUnits.remove(sf)) {
					writer.printf("skipping %s\n", sf.toString());
					// if it's a script, mark it for having compile errors
					if (GhidraScriptUtil.contains(rf)) {
						ScriptInfo info = GhidraScriptUtil.getScriptInfo(rf);
						info.setCompileErrors(true);
					}
				}
			}
		}
		// mark the successful compilations
		for (ResourceFileJavaFileObject sf : compilationUnits) {
			ResourceFile rf = sf.getFile();
			if (GhidraScriptUtil.contains(rf)) {
				ScriptInfo info = GhidraScriptUtil.getScriptInfo(rf);
				info.setCompileErrors(false);
			}
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
		Stream<Object> bjars =
			Files.list(bh.getCompiledBundlesDir()).filter(f -> f.toString().endsWith(".jar")).map(
				f -> {
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
			BundleHost.getSymbolicNameFromSourceDir(srcdir));
		analyzer.setProperty("Bundle-Version", "1.0");
		analyzer.setProperty("Import-Package", "*");
		analyzer.setProperty("Export-Package", "!*.private.*,!*.internal.*,*");
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
				activator_classname = "GeneratedActivator";
				if (!createActivator(bindir, activator_classname, writer)) {
					Msg.error(this, "failed to create activator");
					return;
				}
				// since we add the activator after bndtools built the imports, we should add its imports too
				String imps = ma.getValue(Constants.IMPORT_PACKAGE);
				ma.putValue(Constants.IMPORT_PACKAGE, imps + ",ghidra.app.script.osgi");
			}
			ma.putValue(Constants.BUNDLE_ACTIVATOR, activator_classname);

			// write the manifest
			Files.createDirectories(dmf.getParent());
			try (OutputStream out = Files.newOutputStream(dmf)) {
				manifest.write(out);
			}
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		finally {
			analyzer.close();
		}
	}

	private boolean createActivator(Path bindir, String activator_classname, Writer output)
			throws IOException {
		Path activator_dest = bindir.resolve(activator_classname + ".java");

		try (PrintWriter writer =
			new PrintWriter(Files.newBufferedWriter(activator_dest, Charset.forName("UTF-8")))) {
			writer.println("import ghidra.app.script.osgi.GhidraBundleActivator;");
			writer.println("import org.osgi.framework.BundleActivator;");
			writer.println("import org.osgi.framework.BundleContext;");
			writer.println("public class GeneratedActivator extends GhidraBundleActivator {");
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
			return false;
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

		StandardJavaFileManager fm0 = compiler.getStandardFileManager(null, null, null);
		BundleJavaManager fm = new BundleJavaManager(bh.getHostFramework(), fm0, options);
		Iterable<? extends JavaFileObject> compilationUnits2 =
			fm0.getJavaFileObjectsFromPaths(List.of(activator_dest));
		DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<JavaFileObject>();
		JavaCompiler.CompilationTask task2 =
			compiler.getTask(output, fm, diagnostics, options, null, compilationUnits2);
		if (!task2.call()) {
			for (Diagnostic<? extends JavaFileObject> d : diagnostics.getDiagnostics()) {
				output.write(d.getSource().toString() + ": " + d.getMessage(null) + "\n");
			}
			return false;
		}
		return true;
	}

}
