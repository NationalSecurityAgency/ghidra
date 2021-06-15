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
package ghidra.app.script;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.*;

import javax.tools.*;
import javax.tools.JavaFileObject.Kind;

import generic.jar.ResourceFile;
import ghidra.util.exception.AssertException;

/**
 * A {@link JavaFileManager} that works with Ghidra's {@link ResourceFile}s.
 * 
 * <p>This class is used to dynamically compile Ghidra scripts.
 */
public class ResourceFileJavaFileManager implements JavaFileManager {

	private StandardJavaFileManager fileManager;
	private List<ResourceFile> sourceDirs;
	private Set<ResourceFile> filesToAvoid;

	/**
	 * Create a {@link JavaFileManager} for use by the {@link JavaCompiler}.
	 * 
	 * @param sourceDirs the directories containing source
	 * @param filesToAvoid known "bad" files to hide from the compiler
	 */
	public ResourceFileJavaFileManager(List<ResourceFile> sourceDirs,
			Set<ResourceFile> filesToAvoid) {
		this.sourceDirs = sourceDirs;
		this.filesToAvoid = filesToAvoid;
		JavaCompiler javaCompiler = ToolProvider.getSystemJavaCompiler();
		if (javaCompiler == null) {
			throw new AssertException("Can't find java compiler");
		}
		fileManager = javaCompiler.getStandardFileManager(null, Locale.getDefault(),
			Charset.defaultCharset());
	}

	@Override
	public int isSupportedOption(String option) {
		return fileManager.isSupportedOption(option);
	}

	@Override
	public ClassLoader getClassLoader(Location location) {
		return fileManager.getClassLoader(location);
	}

	@Override
	public Iterable<JavaFileObject> list(Location location, String packageName, Set<Kind> kinds,
			boolean recurse) throws IOException {

		if (location.equals(StandardLocation.SOURCE_PATH)) {
			String relativePath = packageName.replace('.', '/');
			List<JavaFileObject> newResult = new ArrayList<>();
			for (ResourceFile sourceDir : sourceDirs) {
				ResourceFile packageDir =
					relativePath.isEmpty() ? sourceDir : new ResourceFile(sourceDir, relativePath);
				if (packageDir.isDirectory()) {
					gatherFiles(sourceDir, packageDir, newResult, kinds, recurse);
				}
			}
			return newResult;
		}
		return fileManager.list(location, packageName, kinds, recurse);
	}

	private void gatherFiles(ResourceFile root, ResourceFile file, List<JavaFileObject> accumulator,
			Set<Kind> kinds, boolean recurse) {
		List<ResourceFile> listFiles = new ArrayList<>(Arrays.asList(file.listFiles()));
		listFiles.removeAll(filesToAvoid);
		for (ResourceFile resourceFile : listFiles) {
			if (resourceFile.isDirectory()) {
				if (recurse) {
					gatherFiles(root, resourceFile, accumulator, kinds, recurse);
				}
			}
			else {
				for (Kind kind : kinds) {
					if (kind == Kind.CLASS) {
						if (resourceFile.getName().endsWith(".class")) {
							accumulator.add(createFileObject(root, resourceFile, kind));
							break;
						}
					}
					else if (kind == Kind.SOURCE) {
						if (resourceFile.getName().endsWith(".java")) {
							accumulator.add(createFileObject(root, resourceFile, kind));
							break;
						}
					}
				}
			}
		}

	}

	private JavaFileObject createFileObject(ResourceFile root, ResourceFile resourceFile,
			Kind kind) {
		try {
			return new ResourceFileJavaFileObject(root, resourceFile, kind);
		}
		catch (Exception e) {
			// resourceFile should have valid URL;
			throw new AssertException("Unexpected url exception on resource file" + resourceFile);
		}
	}

	@Override
	public String inferBinaryName(Location location, JavaFileObject file) {
		if (file instanceof ResourceFileJavaFileObject) {
			String name = file.getName();
			int lastIndexOf = name.lastIndexOf(".java");
			if (lastIndexOf >= 0) {
				String path = name.substring(0, lastIndexOf);
				path = path.replace('/', '.').replace('\\', '.');
				return path;
			}
			throw new AssertException("Expected name to end in .java but got " + name);
		}
		String inferBinaryName = fileManager.inferBinaryName(location, file);
		return inferBinaryName;
	}

	@Override
	public boolean isSameFile(FileObject a, FileObject b) {
		return a.toUri().equals(b.toUri());
	}

	@Override
	public boolean handleOption(String current, Iterator<String> remaining) {
		return fileManager.handleOption(current, remaining);
	}

	@Override
	public boolean hasLocation(Location location) {
		if (location.equals(StandardLocation.SOURCE_PATH)) {
			return true;
		}
		return fileManager.hasLocation(location);
	}

	@Override
	public JavaFileObject getJavaFileForInput(Location location, String className, Kind kind)
			throws IOException {
		if (!location.equals(StandardLocation.SOURCE_PATH) || "module-info".equals(className)) {
			// Our Ghidra scripts will not use Java 9's module definition file (module-info.java).
			return fileManager.getJavaFileForInput(location, className, kind);
		}
		String relativePath = className.replace('.', '/');
		for (ResourceFile sourceDir : sourceDirs) {
			ResourceFile file = new ResourceFile(sourceDir, relativePath);
			if (file.exists()) {
				return createFileObject(sourceDir, file, kind);
			}
		}
		return null;
	}

	@Override
	public JavaFileObject getJavaFileForOutput(Location location, String className, Kind kind,
			FileObject sibling) throws IOException {
		return fileManager.getJavaFileForOutput(location, className, kind, sibling);
	}

	@Override
	public FileObject getFileForInput(Location location, String packageName, String relativeName)
			throws IOException {
		return fileManager.getFileForInput(location, packageName, relativeName);
	}

	@Override
	public FileObject getFileForOutput(Location location, String packageName, String relativeName,
			FileObject sibling) throws IOException {
		return fileManager.getFileForOutput(location, packageName, relativeName, sibling);
	}

	@Override
	public void flush() throws IOException {
		fileManager.flush();
	}

	@Override
	public void close() throws IOException {
		fileManager.close();
	}

	@Override
	public JavaFileManager.Location getLocationForModule(JavaFileManager.Location location,
			String moduleName) throws IOException {
		return fileManager.getLocationForModule(location, moduleName);
	}

	@Override
	public JavaFileManager.Location getLocationForModule(JavaFileManager.Location location,
			JavaFileObject fo) throws IOException {
		return fileManager.getLocationForModule(location, fo);
	}

	@Override
	public String inferModuleName(JavaFileManager.Location location) throws IOException {
		return fileManager.inferModuleName(location);
	}

	@Override
	public Iterable<Set<JavaFileManager.Location>> listLocationsForModules(
			JavaFileManager.Location location) throws IOException {
		return fileManager.listLocationsForModules(location);
	}

	@Override
	public boolean contains(Location location, FileObject fo) throws IOException {
		return fileManager.contains(location, fo);
	}

	@Override
	public <S> ServiceLoader<S> getServiceLoader(Location location, Class<S> service)
			throws IOException {
		return fileManager.getServiceLoader(location, service);
	}

}
