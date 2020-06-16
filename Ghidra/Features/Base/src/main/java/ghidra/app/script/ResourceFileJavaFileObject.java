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

import java.io.*;
import java.net.URI;

import javax.lang.model.element.Modifier;
import javax.lang.model.element.NestingKind;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;

import generic.jar.ResourceFile;

/**
 * A {@link JavaFileObject} that works with Ghidra's {@link ResourceFileJavaFileManager}.
 * 
 * <p>This class is used to dynamically compile Ghidra scripts.
 */
public class ResourceFileJavaFileObject implements JavaFileObject {

	private ResourceFile file;
	private String pathName;
	private Kind kind;

	/**
	 * Represents a {@link ResourceFile} for a {@link JavaCompiler} via a {@link ResourceFileJavaFileManager}
	 * 
	 * @param sourceRoot the root source directory
	 * @param file the file
	 * @param kind the kind
	 */
	public ResourceFileJavaFileObject(ResourceFile sourceRoot, ResourceFile file, Kind kind) {
		this.file = file;
		this.kind = kind;
		String sourceRootPath = sourceRoot.getAbsolutePath();
		// find relative path, add 1 to get past path separator
		pathName = file.getAbsolutePath().substring(sourceRootPath.length() + 1);
	}

	/**
	 * @return the {@link ResourceFile} this object represents
	 */
	public ResourceFile getFile() {
		return file;
	}

	@Override
	public URI toUri() {
		return file.toURI();
	}

	@Override
	public String getName() {
		return pathName;
	}

	@Override
	public InputStream openInputStream() throws IOException {
		return file.getInputStream();
	}

	@Override
	public OutputStream openOutputStream() throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public Reader openReader(boolean ignoreEncodingErrors) throws IOException {
		return new InputStreamReader(file.getInputStream());
	}

	@Override
	public CharSequence getCharContent(boolean ignoreEncodingErrors) throws IOException {
		Reader openReader = openReader(true);
		BufferedReader in = new BufferedReader(openReader);
		try {
			StringBuffer buffy = new StringBuffer();
			String line;
			while ((line = in.readLine()) != null) {
				buffy.append(line);
				buffy.append("\n");
			}
			return buffy;
		}
		finally {
			in.close();
		}
	}

	@Override
	public Writer openWriter() throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public long getLastModified() {
		return file.lastModified();
	}

	@Override
	public boolean delete() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Kind getKind() {
		return kind;
	}

	@Override
	public boolean isNameCompatible(String compatibleName, Kind testKind) {
		if (compatibleName == null) {
			throw new NullPointerException("simpleName cannot be null");
		}

		if (kind != testKind && testKind == Kind.OTHER) {
			return false;
		}

		String testName = compatibleName + testKind.extension;
		String myName = file.getName();
		if (myName.equals(testName)) {
			return true;
		}

		// check for OSes with non-unique case
		if (myName.equalsIgnoreCase(testName)) {
			ResourceFile canonicalFile = file.getCanonicalFile();
			String myCanonicalName = canonicalFile.getName();
			return myCanonicalName.equals(testName);
		}

		return false;
	}

	@Override
	public NestingKind getNestingKind() {
		return null;
	}

	@Override
	public Modifier getAccessLevel() {
		return null;
	}

	@Override
	public String toString() {
		// Overridden to have stack traces use the name of the file and not this class's name, as
		// Java will use this class to generate the stack trace when we use the compile API.
		return file.getName();
	}
}
