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
package ghidra.formats.gfilesystem;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.*;

import ghidra.util.SystemUtilities;

/**
 * A _F_ile _S_ystem _R_esource _L_ocator, (name and string format patterned after URLs)
 * <p>
 * Used to locate a resource (by name) on a "filesystem", in a recursively nested fashion.
 * <p>
 * The string format of FSRLs is {@code fstype} + <b>"://"</b> + {@code path} + {@code optional_MD5}
 * [ + <b>"|"</b> pipe + {@code FSRL} ]*
 * <p>
 * See {@link #fromPartString(FSRL, String)} for more format info.
 * <p>
 * Read the string format from right-to-left for easiest understanding... ie.
 * "file://z|y://x" reads as "file x inside a filesystem y inside a container file z".
 * <p>
 * FSRL instances are immutable and thread-safe.
 * <p>
 * Examples (pipes shown in red since they are hard to see):
 * <ul>
 * <li><b>file://dir/subdir</b> -- simplest example, locates a file on local computer filesystem.
 * <li><b>file://dir/subdir/example.zip<span style="color:red">|</span>zip://readme.txt</b> -- points to a file named "readme.txt" in a zip file.
 * <li><b>file://dir/subdir/example.zip<span style="color:red">|</span>zip://dir/nested.tar<span style="color:red">|</span>tar://file.txt</b> -- points to
 * a file inside a TAR archive, which is inside a ZIP archive, which is on the local filesystem.
 * <li><b>file://dir/subdir/example.zip?MD5=1234567<span style="color:red">|</span>zip://readme.txt?MD5=987654</b> --
 * points to a file named "readme.txt" (with a MD5 hash) in a zip file (that has another
 * MD5 hash).
 * </ul>
 * <p>
 * See {@link FSRLRoot} for examples of how FSRL and FSRLRoot's are related.
 * <p>
 * FSRL's can be created either piecemeal, from the bottom up, starting with a root filesystem
 * FSRL and calling {@link #appendPath(String)} or {@link FSRLRoot#nestedFS(FSRL, String)} methods
 * to create deeper and deeper nested FSRLs,
 * <p>
 * or
 * <p>
 * FSRL's can be created from strings using {@link #fromString(String)}.
 * <p>
 * FSRLs that have a MD5 value are {@link FileSystemService#getFullyQualifiedFSRL(FSRL, ghidra.util.task.TaskMonitor) "fully qualified"}.
 * <p>
 */
public class FSRL {
	public static final String PARAM_MD5 = "MD5";

	/**
	 * Creates a {@link FSRL} from a raw string.  The parent portions of the FSRL
	 * are not intern()'d so will not be shared with other FSRL instances.
	 * <p>
	 * See {@link #fromPartString(FSRL, String)} for details of character encoding fixups.
	 * <p>
	 * @param fsrlStr something like "fstype://path/path|fs2type://path2/path2|etc://etc/etc"
	 * @return new {@link FSRL} instance, never null
	 * @throws MalformedURLException if empty string or bad format
	 */
	public static FSRL fromString(String fsrlStr) throws MalformedURLException {
		return fromString(null, fsrlStr);
	}

	/**
	 * Creates a {@link FSRL} from a raw string.
	 * <p>
	 * See {@link #fromPartString(FSRL, String)} for details of character encoding fixups.
	 * <p>
	 * @param parent Parent {@link FSRL}
	 * @param fsrlStr something like "fstype://path/path|fs2type://path2/path2|etc://etc/etc"
	 * @return new {@link FSRL} instance, never null
	 * @throws MalformedURLException if empty string or bad format
	 */
	public static FSRL fromString(FSRL parent, String fsrlStr) throws MalformedURLException {
		String[] partStrs = fsrlStr.trim().split("\\|");
		for (String partStr : partStrs) {
			FSRL fsrl = fromPartString(parent, partStr);
			parent = fsrl;
		}
		return parent;
	}

	/**
	 * Creates a single {@link FSRL} from a FSRL-part string.
	 * <p>
	 * A FSRL-part string is defined as protocol_string + "://" + path_string + "?" + param_string.
	 * <p>
	 * There should be  no '|' separator characters present in the FSRL-part string.
	 * <p>
	 * Backslash characters in the path are normalized to forward slashes after decoding any
	 * hex encoded character values (ie. %20 becomes ' ' (32) ).  See {@link FSUtilities#escapeEncode(String)}.
	 *
	 * @param containerFile the parent container file that contains this filesystem's data
	 * @param partStr the string that defines this portion of the FSRL
	 * @return new FSRL instance, who's FSLRRoot is parented on containerFile.
	 *
	 * @throws MalformedURLException if the partStr is formatted incorrectly
	 */
	private static FSRL fromPartString(FSRL containerFile, String partStr)
			throws MalformedURLException {
		partStr = partStr.trim();
		int colonSlashSlash = partStr.indexOf("://");
		if (colonSlashSlash <= 0) {
			throw new MalformedURLException("Missing protocol in " + partStr);
		}
		String proto = partStr.substring(0, colonSlashSlash);
		String path = partStr.substring(colonSlashSlash + 3);

		int paramStart = path.indexOf("?");
		String md5 = null;
		if (paramStart >= 0) {
			String params = path.substring(paramStart + 1);
			path = path.substring(0, paramStart);
			Map<String, String> paramMap = getParamMapFromString(params);
			md5 = paramMap.get(FSRL.PARAM_MD5);
		}

		FSRLRoot fsRoot = FSRLRoot.nestedFS(containerFile, proto);
		String decodedPath = FSUtilities.escapeDecode(path);
		decodedPath = decodedPath.replace('\\', '/');
		if (decodedPath.isEmpty()) {
			decodedPath = null;
		}
		return new FSRL(fsRoot, decodedPath, md5);
	}

	private static Map<String, String> getParamMapFromString(String paramsStr)
			throws MalformedURLException {
		Map<String, String> paramMap = new HashMap<>();
		String[] fields = paramsStr.split("&");
		for (String field : fields) {
			int equalIdx = field.indexOf('=');
			String name = (equalIdx > 0) ? field.substring(0, equalIdx) : "";
			String value = (equalIdx >= 0) ? field.substring(equalIdx + 1) : field;

			name = FSUtilities.escapeDecode(name);
			value = FSUtilities.escapeDecode(value);

			paramMap.put(name, value);
		}
		return paramMap;
	}

	protected final FSRL parent;
	protected final String path;
	private final String md5;

	/**
	 * Protected constructor called by static factory methods such as {@link #fromString(String)}
	 * or methods that return a new instance such as {@link #withPath(String)}.
	 *
	 * @param parent FSRL parent, null if this instance is root FSRLRoot
	 * @param path String path, meaning dependent on context
	 */
	protected FSRL(FSRL parent, String path) {
		this(parent, path, null);
	}

	/**
	 * Protected constructor called by static factory methods such as {@link #fromString(String)}
	 * or methods that return a new instance such as {@link #withPath(String)}.
	 *
	 * @param parent FSRL parent, null if this instance is root FSRLRoot
	 * @param path String path, meaning dependent on context
	 * @param md5 hex string with the md5 hash of the file this FSRL points to, null ok.
	 */
	protected FSRL(FSRL parent, String path, String md5) {
		this.parent = parent;
		this.path = path;
		this.md5 = md5;
	}

	/**
	 * Returns the {@link FSRLRoot} object that represents the entire
	 * {@link GFileSystem filesystem} for this FSRL.
	 * <p>
	 * Never returns NULL, and calling getFS() on a {@link FSRLRoot} object
	 * returns itself.
	 * @return {@link FSRLRoot} instance that is the parent of this {@link FSRL}, never
	 * null.
	 */
	public FSRLRoot getFS() {
		return (FSRLRoot) parent;
	}

	/**
	 * Returns the number of {@link FSRLRoot}s there are in this {@link FSRL}.
	 * <p>
	 * A single level FSRL such as "file://path" will return 1.<br>
	 * A two level FSRL such as "file://path|subfs://path2" will return 2.<br>
	 * etc.<br>
	 *
	 * @return number of levels in this FSRL, min value returned is 1.
	 */
	public int getNestingDepth() {
		int depth = 0;
		FSRLRoot root = getFS();
		while (root != null) {
			depth++;
			root = root.hasContainer() ? root.getContainer().getFS() : null;
		}
		return depth;
	}

	/**
	 * Returns the full path/filename of this FSRL.  Does not include parent filesystem path
	 * or info.
	 * <p>
	 * "file://path|subfs://subpath/blah" returns "/subpath/blah"
	 * <p>
	 * May return null if this instance is a {@link FSRLRoot}.
	 *
	 * @return string path and filename of this object.  Null if this {@link FSRL} is a
	 * {@link FSRLRoot}.
	 */
	public String getPath() {
		return path;
	}

	/**
	 * Returns the name portion of this FSRL's path, everything after the last '/'
	 * <p>
	 * "file://path/name.ext" returns "name.ext"
	 *
	 * @return name portion of this FSRL path, or null if path is null also.
	 */
	public String getName() {
		if (path == null) {
			return null;
		}
		int cp = path.lastIndexOf('/');
		return cp >= 0 ? path.substring(cp + 1) : path;
	}

	/**
	 * Returns the name portion of the FSRL part at parent depth {@code nestedDepth}, where 0
	 * is ourself (equiv to just calling {@link #getName()}, 1 is the parent
	 * container's name, etc.
	 * <p>
	 * @param nestedDepth relative parent index of FSRL part to query, 0 == this instance.
	 * @return name portion of the path of the specified FSRL part.
	 * @throws IOException if nestedDepth is larger than number of FSRL parent parts.
	 */
	public String getName(int nestedDepth) throws IOException {
		FSRL current = this;
		for (int depth = 0; depth < nestedDepth; depth++) {
			FSRL parentContainer = current.getFS().getContainer();
			if (parentContainer == null) {
				throw new IOException(
					"Unknown requested FSRL parent, requested depth " + nestedDepth + ", only " +
						getNestingDepth() + " available in " + this.toString());
			}
			current = parentContainer;
		}
		return current.getName();
	}

	/**
	 * Returns the MD5 string associated with this file.
	 * <p>
	 * NULL if no MD5 value present.
	 * <p>
	 * @return md5 string associated with this file object, or null if not present.
	 */
	public String getMD5() {
		return md5;
	}

	/**
	 * Creates a new {@link FSRL} instance, using the same information as this instance,
	 * but with a new {@link #getMD5() MD5} value.
	 *
	 * @param newMD5 string md5
	 * @return new {@link FSRL} instance with the same path and the specified md5 value.
	 */
	public FSRL withMD5(String newMD5) {
		return new FSRL(getFS(), path, newMD5);
	}

	/**
	 * Creates a new {@link FSRL} instance, using the same {@link FSRLRoot} as this instance,
	 * but with a new path.
	 * <p>
	 * See also {@link #appendPath(String)}.
	 * <p>
	 * @param newpath string path
	 * @return new {@link FSRL} instance with the specified path.
	 */
	public FSRL withPath(String newpath) {
		return new FSRL(getFS(), newpath);
	}

	/**
	 * Creates a new {@link FSRL} instance using the same path and other metadata
	 * present in the {@code copyPath} instance.
	 * <p>
	 * Used when re-root'ing a FSRL path onto another parent object (usually during intern()'ing)
	 *
	 * @param copyPath
	 * @return new FSRL instance
	 */
	public FSRL withPath(FSRL copyPath) {
		return new FSRL(getFS(), copyPath.getPath(), copyPath.getMD5());
	}

	/**
	 * Creates a new {@link FSRL} instance, using the same {@link FSRLRoot} as this instance,
	 * combining the current {@link #getPath() path} with the {@code relPath} value.
	 * <p>
	 * @param relPath
	 * @return new {@link FSRL} instance with additional path appended.
	 */
	public FSRL appendPath(String relPath) {
		String basePath = getPath();
		return new FSRL(getFS(),
			FSUtilities.appendPath((basePath == null) ? "/" : basePath, relPath));
	}

	/**
	 * Creates a new {@link FSRLRoot} instance that is a child of this FSRL.
	 * <p>
	 * See {@link FSRLRoot#nestedFS(FSRL, FSRLRoot)} and {@link FSRLRoot#nestedFS(FSRL, String)}.
	 * @param fstype file system type string.
	 * @return new {@link FSRLRoot} instance
	 */
	public FSRLRoot makeNested(String fstype) {
		return FSRLRoot.nestedFS(this, fstype);
	}

	/**
	 * Returns a string containing the full FSRL.
	 * <p>
	 * Example: "file://path|subfs://blah?MD5=1234567"
	 *
	 * @return string with full FSRL
	 */
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		appendToStringBuilder(sb, true, true, true);
		return sb.toString();
	}

	/**
	 * Returns a string containing the full FSRL, excluding MD5 portions.
	 *
	 * @return string with full FSRL, excluding MD5 portions.
	 */
	public String toPrettyString() {
		StringBuilder sb = new StringBuilder();
		appendToStringBuilder(sb, true, false, true);
		return sb.toString();
	}

	/**
	 * Returns a string containing the full FSRL, without FS "fstype://" portions
	 * <p>
	 * Example:
	 * <p>
	 * {@code "fsrl://path/filename?MD5=1234|subfsrl://subpath/subfile"}
	 * <p>
	 * will result in
	 * <p>
	 * {@code "path/filename|subpath/subfile"}.
	 *
	 * @return formatted string such as: "path/filename|subpath/subfile"
	 */
	public String toPrettyFullpathString() {
		StringBuilder sb = new StringBuilder();
		appendToStringBuilder(sb, true, false, false);
		return sb.toString();
	}

	protected void appendToStringBuilder(StringBuilder sb, boolean recurse, boolean includeParams,
			boolean includeFSRoot) {
		parent.appendToStringBuilder(sb, recurse, includeParams, includeFSRoot);
		if (path != null) {
			sb.append(FSUtilities.escapeEncode(path));
		}
		// no need to encode md5 string since all hexdigit chars are safe
		if (md5 != null && includeParams) {
			sb.append("?").append(PARAM_MD5).append("=").append(md5);
		}
	}

	/**
	 * Returns a string containing just the current {@link FSRL} protocol and path.
	 * <p>
	 * Example: "file://path|subfs://blah?MD5=123456" returns "subfs://blah?MD5=123456"
	 *
	 * @return string containing just the current {@link FSRL} protocol and path.
	 */
	public String toStringPart() {
		StringBuilder sb = new StringBuilder();
		appendToStringBuilder(sb, false, true, true);
		return sb.toString();
	}

	/**
	 * Splits a {@link FSRL} into a {@link List}, with each element pointing to
	 * each level of the full FSRL.
	 * <p>
	 * Example: "file://path|subfs://blah|subfs2://blah2"
	 * <p>
	 * Produces a list of 3 elements:<br>
	 * "file://path"<br>
	 * "file://path|subfs://blah"<br>
	 * "file://path|subfs://blah|subfs2://blah2"
	 * <p>
	 * @return {@link List} of {@link FSRL} elements pointing to each level of this FSRL.
	 */
	public List<FSRL> split() {
		List<FSRL> result = new ArrayList<>();
		FSRL current = this;
		while (current != null) {
			result.add(0, current);
			current = current.getFS().getContainer();
		}
		return result;
	}

	/**
	 * Returns true if the two FSRLs are the same, excluding any MD5 values.
	 *
	 * @param fsrlStr string-ified {@link FSRL}
	 * @return boolean true if this instance is the same as the specified string-ified fsrl,
	 * ignoring any md5 values.
	 */
	public boolean isEquivalent(String fsrlStr) {
		if (fsrlStr == null) {
			return false;
		}
		String s = toString();
		return s.equals(fsrlStr) ||
			(getMD5() != null && s.startsWith(fsrlStr) &&
				s.substring(fsrlStr.length()).startsWith("?MD5=") &&
				s.length() == fsrlStr.length() + 37) ||
			(getMD5() == null && fsrlStr.startsWith(s) &&
				fsrlStr.substring(s.length()).startsWith("?MD5=") &&
				fsrlStr.length() == s.length() + 37);
	}

	/**
	 * Returns true if the two {@link FSRL}s are the same, excluding any MD5 values.
	 *
	 * @param other {@link FSRL} to compare with
	 * @return boolean true if this instance is the same as the specified FSRL, ignoring
	 * any md5 values.
	 */
	public boolean isEquivalent(FSRL other) {
		if (this == other) {
			return true;
		}
		if (other == null) {
			return false;
		}

		// Parent
		if (parent == null) {
			if (other.parent != null) {
				return false;
			}
		}
		else if (!parent.isEquivalent(other.parent)) {
			return false;
		}

		// Path
		return Objects.equals(path, other.path);
	}

	/**
	 * Returns {@code true} if this object is a child or descendant of the
	 * specified {@code potentialParent} parameter.
	 * <p>
	 * @param potentialParent {@link FSRL} to test against
	 * @return boolean true if the specified {@link FSRL} is a parent (ignoring md5 hashes)
	 * of this instance.
	 */
	public boolean isDescendantOf(FSRL potentialParent) {
		if (isEquivalent(potentialParent)) {
			return false;
		}
		List<FSRL> split = split();
		for (int i = split.size() - 1; i >= 0; i--) {
			FSRL myPart = split.get(i);
			if (myPart.getFS().equals(potentialParent.getFS()) &&
				(SystemUtilities.isEqual(myPart.getPath(), potentialParent.getPath()) ||
					isParentPath(potentialParent.getPath(), myPart.getPath()))) {
				return true;
			}
		}
		return false;
	}

	private static boolean isParentPath(String parent, String child) {
		return child.startsWith(parent) && child.length() > parent.length() &&
			(parent.endsWith("/") || child.charAt(parent.length()) == '/');
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((parent == null) ? 0 : parent.hashCode());
		result = prime * result + ((path == null) ? 0 : path.hashCode());
		result = prime * result + ((md5 == null) ? 0 : md5.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (!(obj instanceof FSRL)) {
			return false;
		}
		FSRL other = (FSRL) obj;

		// Parent
		if (parent == null) {
			if (other.parent != null) {
				return false;
			}
		}
		else if (!parent.equals(other.parent)) {
			return false;
		}

		// Path
		if (path == null) {
			if (other.path != null) {
				return false;
			}
		}
		else if (!path.equals(other.path)) {
			return false;
		}

		// MD5
		if (md5 == null) {
			if (other.md5 != null) {
				return false;
			}
		}
		else if (!md5.equals(other.md5)) {
			return false;
		}
		return true;
	}
}
