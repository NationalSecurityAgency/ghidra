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
