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
package docking.widgets.filechooser;

import java.io.File;
import java.io.IOException;

/**
 * An extension of File that does not translate to the
 * native operating system's file separator.
 * For example, on Windows:
 * <br>
 * <code>File f = new File("c:/temp/foo.txt");</code><br>
 * <code>String path = f.getAbsolutePath();</code><br>
 * In this case, path equals "c:\temp\foo.txt".
 * However using GhidraFile, path would still equal "c:/temp/foo.txt"
 * 
 */
public class GhidraFile extends File {
	private static final long serialVersionUID = 1L;

	private char nativeSeparator = separatorChar;

    /**
     * Construct a new GhidraFile.
     * @param parent the parent directory; eg, "c:\temp"
     * @param child the child file name; eg, "foo.txt"
     * @param separator the separator character; eg, '/' or '\'
     */
    public GhidraFile(String parent, String child, char separator) {
        super(parent, child);
        this.nativeSeparator = separator;
    }

    /**
     * Construct a new GhidraFile.
     * @param path the path to the file; eg, "c:\temp\foo.txt" or "temp\foo.txt"
     * @param separator the separator character; eg, '/' or '\'
     */
    public GhidraFile(String path, char separator) {
        super(path);
        this.nativeSeparator = separator;
    }

    /**
     * Construct a new GhidraFile.
     * @param parent the parent file path
     * @param name the name of the file
     * @param separator the separator character; eg, '/' or '\'
     */
    public GhidraFile(File parent, String name, char separator) {
        super(parent, name);
        this.nativeSeparator = separator;
    }

    /**
     * @see java.io.File#getAbsoluteFile()
     */
    @Override
    public File getAbsoluteFile() {
        if (nativeSeparator == separatorChar) {
            return super.getAbsoluteFile();
        }
        return this;
    }

    /**
     * @see java.io.File#getCanonicalFile()
     */
    @Override
    public File getCanonicalFile() throws IOException {
        if (nativeSeparator == separatorChar) {
            return super.getCanonicalFile();
        }
        return this;
    }

    /**
     * @see java.io.File#getAbsolutePath()
     */
    @Override
    public String getAbsolutePath() {
        if (nativeSeparator == separatorChar) {
            return super.getAbsolutePath();
        }
        return getPath();
    }

    /**
     * @see java.io.File#getCanonicalPath()
     */
    @Override
    public String getCanonicalPath() throws IOException {
        if (nativeSeparator == separatorChar) {
            return super.getCanonicalPath();
        }
        return getPath();
    }

    /**
     * @see java.io.File#getParent()
     */
    @Override
    public String getParent() {
        if (nativeSeparator == separatorChar) {
            return super.getParent();
        }
        String parent = super.getParent();
        if (parent == null) {
            return null;
        }
        return parent.replace(separatorChar, nativeSeparator);
    }

    /**
     * @see java.io.File#getParentFile()
     */
    @Override
    public File getParentFile() {
        if (nativeSeparator == separatorChar) {
            return super.getParentFile();
        }
        if (getParent() == null) {
            return null;
        }
        return new GhidraFile(getParent(), nativeSeparator);
    }

    /**
     * @see java.io.File#getPath()
     */
    @Override
    public String getPath() {
        if (nativeSeparator == separatorChar) {
            return super.getPath();
        }
        return super.getPath().replace(separatorChar, nativeSeparator);
    }
}
