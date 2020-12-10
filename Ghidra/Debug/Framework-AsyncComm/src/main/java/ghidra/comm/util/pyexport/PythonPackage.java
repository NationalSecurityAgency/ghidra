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

import java.io.*;
import java.nio.file.*;
import java.util.*;

import org.apache.commons.collections4.map.LazyMap;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.text.StrSubstitutor;

import ghidra.graph.algo.SorterException;

/**
 * A model of a Python package
 * 
 * It contains classes and subpackages.
 * 
 * This model neglects modules, because it is meant for automatic porting of Java classes to Python.
 * Like Java, each Python class is exported to its own file.
 */
@SuppressWarnings("deprecation") // FIXME: Remove pyexport package
class PythonPackage implements Comparable<PythonPackage> {
	private final PythonPackage parent;
	private final String pkgName;

	private Map<String, PythonPackage> subPackages;
	private final Map<String, PythonClass> classes;

	boolean isExported;

	PythonPackage(GeneratePython generator, String pkgName, PythonPackage parent) {
		this.pkgName = pkgName;
		this.parent = parent;

		subPackages =
			LazyMap.lazyMap(new HashMap<>(), (name) -> new PythonPackage(generator, name, this));
		classes =
			LazyMap.lazyMap(new TreeMap<>(), (name) -> new PythonClass(generator, name, this));
	}

	boolean generate(Path outputRoot) throws IOException, SorterException {
		boolean doCreate = false;
		for (PythonPackage sub : subPackages.values()) {
			doCreate |= sub.generate(outputRoot);
		}
		for (PythonClass cls : classes.values()) {
			if (cls.isExported) {
				doCreate = true;
			}
		}
		if (!doCreate) {
			return false;
		}

		for (PythonClass cls : classes.values()) {
			if (cls.isExported) {
				cls.generate(outputRoot);
			}
		}

		final Path out = outputRoot.resolve(getPath()).resolve("__init__.py");
		Files.createDirectories(out.getParent());
		Map<String, String> varMap = new HashMap<>();
		varMap.put("relpath", getPath().toString());
		StrSubstitutor subst = new StrSubstitutor(varMap);
		try (PrintWriter wr = new PrintWriter(Files.newBufferedWriter(out))) {
			try (BufferedReader rd = new BufferedReader(new InputStreamReader(
				GeneratePython.class.getResourceAsStream("__init__.py.template")))) {
				String line;
				while (null != (line = rd.readLine())) {
					wr.println(subst.replace(line));
				}
			}
		}
		final Path init = outputRoot.resolve("classes").resolve(getPath()).resolve("__init__.py");
		Files.createDirectories(init.getParent());
		if (Files.notExists(init)) {
			Files.createFile(init);
		}
		return true;
	}

	public PythonClass getClass(String name) {
		String[] parts = name.split("\\.", 2);
		if (parts.length == 1) {
			return classes.get(parts[0]);
		}
		return subPackages.get(parts[0]).getClass(parts[1]);
	}

	public String getFullName() {
		return StringUtils.join(getPath(), ".");
	}

	public Path getPath() {
		if (parent == null) {
			return Paths.get(pkgName);
		}
		return parent.getPath().resolve(pkgName);
	}

	public PythonPackage getSubPackage(String subPkgName) {
		String[] parts = subPkgName.split("\\.", 2);
		PythonPackage next = subPackages.get(parts[0]);
		if (parts.length == 1) {
			return next;
		}
		return next.getSubPackage(parts[1]);
	}

	public boolean isExported() {
		if (isExported) {
			return true;
		}
		if (parent == null) {
			return false;
		}
		return parent.isExported();
	}

	@Override
	public int compareTo(PythonPackage that) {
		return this.getFullName().compareTo(that.getFullName());
	}
}
