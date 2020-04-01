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

/**
 * The BundlePath class represents the runtime state and user preferences for OSGi bundles in Ghidra.  
 */
public class BundlePath extends Path {
	final Type type;

	boolean active = false;
	boolean busy = false;
	String summary;

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

	public Type getType() {
		return type;
	}

	BundlePath(String path, boolean enabled, boolean readonly) {
		super(path, enabled, false /*editable */, readonly);
		type = getType(getPath());
	}

	BundlePath(ResourceFile path, boolean enabled, boolean readonly) {
		super(path, enabled, false /* editable */, readonly);
		type = getType(getPath());
	}

	public boolean isDirectory() {
		return getPath().isDirectory();
	}

	public boolean isActive() {
		return active;
	}

	@Override
	public boolean isEditable() {
		return false;
	}

	public void setActive(boolean b) {
		active = b;
	}

	public void setBusy(boolean b) {
		busy = b;
	}

	public boolean getBusy() {
		return busy;
	}

	public void setSummary(String summary) {
		this.summary = summary;
	}

	public String getSummary() {
		return summary;
	}

}
