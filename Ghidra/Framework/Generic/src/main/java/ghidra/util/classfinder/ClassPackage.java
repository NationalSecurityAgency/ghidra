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
package ghidra.util.classfinder;

import java.io.*;
import java.util.*;

import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

class ClassPackage {

	private static final FileFilter CLASS_FILTER =
		pathname -> pathname.getName().endsWith(".class");

	private Set<String> classNames = new HashSet<>();
	private Set<Class<?>> classes = null;
	private List<ClassPackage> children = new ArrayList<>();
	private File rootDir;
	private String packageName;

	ClassPackage(File rootDir, String packageName, TaskMonitor monitor) throws CancelledException {
		monitor.checkCanceled();
		this.rootDir = rootDir;
		this.packageName = packageName;
		scanClasses();
		scanSubPackages(monitor);
	}

	private void scanClasses() {

		classNames.clear();
		classes = new HashSet<>();

		String path = rootDir.getAbsolutePath();
		List<String> allClassNames = getAllClassNames();
		for (String className : allClassNames) {

			Class<?> c = ClassFinder.loadExtensionPoint(path, className);
			if (c != null) {
				classes.add(c);
				classNames.add(c.getName());
			}
		}

	}

	private void scanSubPackages(TaskMonitor monitor) throws CancelledException {
		children.clear();
		File dir = getPackageDir(rootDir, packageName);
		File[] subdirs = dir.listFiles();
		if (subdirs == null) {
			Msg.debug(this, "Directory does not exist: " + dir);
			return;
		}

		for (File subdir : subdirs) {
			if (!subdir.isDirectory()) {
				continue;
			}

			monitor.checkCanceled();
			String pkg = subdir.getName();
			if (pkg.contains(".")) {
				// java can't handle dir names with '.'-- it conflicts with the package structure
				continue;
			}

			if (packageName.length() > 0) {
				pkg = packageName + "." + pkg;
			}

			monitor.setMessage("scanning package: " + pkg);
			children.add(new ClassPackage(rootDir, pkg, monitor));
		}
	}

	void rescan(TaskMonitor monitor) throws CancelledException, FileNotFoundException {

		monitor.checkCanceled();

		scanClasses();

		File dir = getPackageDir(rootDir, packageName);
		String rootPath = rootDir.getAbsolutePath();
		String dirPath = dir.getAbsolutePath();
		dirPath = dirPath.substring(rootPath.length());

		monitor.setMessage("scanning directory: " + rootDir.getName() + dirPath);
		File[] subdirs = dir.listFiles();
		if (subdirs == null) {
			Msg.debug(this, "Directory does not exist: " + dir);
			return;
		}

		Set<String> pkgNames = new HashSet<>();
		for (File subdir : subdirs) {
			monitor.checkCanceled();
			if (!subdir.isDirectory()) {
				continue;
			}

			String name = subdir.getName();
			if (name.contains(".")) {
				// java can't handle dir names with '.'-- it conflicts with the package structure
				continue;
			}

			if (packageName.length() > 0) {
				name = packageName + "." + name;
			}
			pkgNames.add(name);
		}

		Iterator<ClassPackage> classPackageIterator = children.iterator();
		while (classPackageIterator.hasNext()) {
			monitor.checkCanceled();
			ClassPackage pkg = classPackageIterator.next();
			if (!pkgNames.contains(pkg.packageName)) {
				classPackageIterator.remove();
			}
			else {
				pkg.rescan(monitor);
				pkgNames.remove(pkg.packageName);
			}
		}

		Iterator<String> packageNameIterator = pkgNames.iterator();
		while (packageNameIterator.hasNext()) {
			monitor.checkCanceled();
			String pkgName = packageNameIterator.next();
			children.add(new ClassPackage(rootDir, pkgName, monitor));
		}
	}

	private File getPackageDir(File lRootDir, String lPackageName) {
		return new File(lRootDir, lPackageName.replace('.', File.separatorChar));
	}

	void getClasses(Set<Class<?>> set, TaskMonitor monitor) throws CancelledException {
		set.addAll(classes);

		Iterator<ClassPackage> classPackageIterator = children.iterator();
		while (classPackageIterator.hasNext()) {
			monitor.checkCanceled();
			ClassPackage subPkg = classPackageIterator.next();
			subPkg.getClasses(set, monitor);
		}
	}

	private List<String> getAllClassNames() {
		File dir = getPackageDir(rootDir, packageName);
		File[] files = dir.listFiles(CLASS_FILTER);
		if (files == null) {
			return Collections.emptyList();
		}

		List<String> results = new ArrayList<>(files.length);
		for (File file : files) {
			String name = file.getName();
			name = name.substring(0, name.length() - 6);
			if (packageName.length() > 0) {
				name = packageName + "." + name;
			}
			results.add(name);
		}
		return results;
	}
}
