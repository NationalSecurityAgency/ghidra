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
package ghidra.comm.util.pyexport;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.Map.Entry;

import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.lang3.StringUtils;

import ghidra.comm.packet.Packet;
import ghidra.generic.util.datastruct.TreeSetValuedTreeMap;

/**
 * A model of a Python class
 * 
 * It contains a list of imports, class-level assignments, base classes, and other lines of code
 * 
 * This model neglects modules, because it is meant for automatic porting of Java classes to Python.
 * Like Java, each Python class is exported to its own file.
 */
class PythonClass implements Comparable<PythonClass> {
	private final GeneratePython generator;

	private final PythonPackage pkg;
	private final MultiValuedMap<String, String> libImports = new TreeSetValuedTreeMap<>();
	private final String clsName;
	private final Map<String, String> assigns = new LinkedHashMap<>();
	private final Map<String, String> postAssigns = new LinkedHashMap<>();
	private final Set<PythonClass> bases = new LinkedHashSet<>();
	private final Set<PythonClass> imports = new TreeSet<>();
	private final List<String> lines = new ArrayList<>();

	boolean isExported = false;

	PythonClass(GeneratePython generator, String clsName, PythonPackage pkg) {
		this.generator = generator;
		this.clsName = clsName;
		this.pkg = pkg;
	}

	void addImport(String module, String... names) {
		for (String name : names) {
			libImports.put(module, name);
		}
	}

	void addAssign(String var, String val) {
		assigns.put(var, val);
	}

	void addPostAssign(String var, String val) {
		postAssigns.put(var, val);
	}

	void addBase(PythonClass cls) {
		addImport(cls);
		bases.add(cls);
	}

	void addImport(PythonClass cls) {
		imports.add(cls);
	}

	void preLine() {
		preLine(null);
	}

	void preLine(String line) {
		lines.add(0, line);
	}

	void addLine() {
		lines.add(null);
	}

	void addLine(String line) {
		lines.add(line);
	}

	void generate(Path outputRoot) throws IOException {
		String pyClsName = getPythonShortName();
		final Path out = outputRoot.resolve("classes").resolve(pkg.getPath())
			.resolve("_class_" + pyClsName + ".py");
		Files.createDirectories(out.getParent());
		try (PrintWriter wr = new PrintWriter(Files.newBufferedWriter(out))) {
			wr.println("# DO NOT MODIFY: This file was automatically generated");
			wr.println();
			for (Entry<String, Collection<String>> ent : libImports.asMap().entrySet()) {
				wr.println(
					"from " + ent.getKey() + " import " + StringUtils.join(ent.getValue(), ", "));
			}
			if (!libImports.isEmpty()) {
				wr.println();
			}
			Set<String> importPkgs = new TreeSet<>();
			for (PythonClass imp : imports) {
				importPkgs.add(imp.getImportPkg(true));
			}
			for (String imp : importPkgs) {
				wr.println("import " + imp);
			}
			if (importPkgs.size() > 0) {
				wr.println();
			}
			PythonClass pyPkt = generator.packetToPyClass(Packet.class);
			wr.println("from " + pyPkt.pkg.getFullName() + " import field, typedesc");
			wr.println();
			wr.println();
			wr.print("class " + pyClsName);
			if (bases.size() > 0) {
				wr.print("(");
				boolean first = true;
				for (PythonClass base : bases) {
					if (!first) {
						wr.print(", ");
					}
					first = false;
					wr.print(base.getFullName(true));
				}
				wr.print(")");
			}
			wr.println(":");
			if (assigns.size() == 0 && lines.size() == 0) {
				wr.println("    pass");
				return;
			}
			// TODO: Export doc?
			for (Entry<String, String> assign : assigns.entrySet()) {
				wr.println(String.format("    %s = %s", assign.getKey(), assign.getValue()));
			}
			for (String line : lines) {
				if (line == null) {
					wr.println();
				}
				else {
					wr.println("    " + line);
				}
			}
			for (Entry<String, String> post : postAssigns.entrySet()) {
				wr.println(String.format("%s.%s = %s", pyClsName, post.getKey(), post.getValue()));
			}
		}
	}

	public String getFullName(boolean internal) {
		return getImportPkg(internal) + "." + getPythonShortName();
	}

	public String getImportPkg(boolean internal) {
		String pkgName = pkg.getFullName();
		if (internal && pkg.isExported()) {
			if ("".equals(pkgName)) {
				return "classes._class_" + getPythonShortName();
			}
			return "classes." + pkgName + "._class_" + getPythonShortName();
		}
		return pkgName;
	}

	public String getPythonShortName() {
		return clsName.replace('$', '_');
	}

	@Override
	public int compareTo(PythonClass that) {
		return this.getFullName(false).compareTo(that.getFullName(false));
	}

	@Override
	public String toString() {
		return getFullName(false);
	}
}
