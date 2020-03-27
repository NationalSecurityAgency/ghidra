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
package ghidra.app.plugin.core.script.osgi;

import java.io.File;

import generic.jar.ResourceFile;
import generic.util.Path;

public class BundlePath extends Path {
	boolean active = false;

	public static enum Type {
		BndScript, Jar, SourceDir, INVALID
	}

	static public Type getType(File f) {
		if (f.isDirectory()) {
			return Type.SourceDir;
		}
		String n = f.getName().toLowerCase();
		if (n.endsWith(".bnd")) {
			return Type.BndScript;
		}
		if (n.endsWith(".jar")) {
			return Type.Jar;
		}
		return Type.INVALID;
	}

	static public Type getType(ResourceFile rf) {
		if (rf.isDirectory()) {
			return Type.SourceDir;
		}
		String n = rf.getName().toLowerCase();
		if (n.endsWith(".bnd")) {
			return Type.BndScript;
		}
		if (n.endsWith(".jar")) {
			return Type.Jar;
		}
		return Type.INVALID;
	}

	final Type type;

	public BundlePath(File path) {
		super(path);
		type = getType(getPath());
	}

	public Type getType() {
		return type;
	}

	public BundlePath(ResourceFile rf) {
		super(rf);
		type = getType(getPath());
	}

	public BundlePath(String absolutePath) {
		super(absolutePath);
		type = getType(getPath());
	}

	public BundlePath(String a, boolean b, boolean c, boolean d) {
		super(a, b, c, d);
		type = getType(getPath());
	}

	public BundlePath(ResourceFile a, boolean b, boolean c, boolean d) {
		super(a, b, c, d);
		type = getType(getPath());
	}

	public boolean isActive() {
		return active;
	}

	public void setActive(Boolean b) {
		active = b;
	}

	public boolean isDirectory() {
		return getPath().isDirectory();
	}

}
