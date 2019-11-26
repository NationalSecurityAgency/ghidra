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

/**
 * A type of {@link FSRL} that is specific to the filesystem's identity.
 *
 * A FSRL's parent is always a FSRLRoot.
 * <p>
 * A FSRLRoot's parent is always a FSRL (ie. the container the filesystem data is in), or null.
 * <p>
 * Examples of relationship between FSRL and FSRLRoots:
 * <p>
 * <ul>
 * 	<li>FSRLRoot [ file:// ]<br>
 *	  "file://"
 * 	<li>{@literal FSRLRoot [ file:// ]  <---- FSRL [ /filename.txt ]}<br>
 * 	  "file:///filename.txt"
 *  <li>{@literal FSRLRoot [ file:// ]  <---- FSRL [ /filename.txt ] <--- FSRLRoot [ subfs:// ]}<br>
 *    "file:///filename.txt|subfs://"
 * </ul>
 */
public class FSRLRoot extends FSRL {
	/**
	 * Creates a {@link FSRLRoot} without a parent container, using the supplied
	 * {@code protocol} string as its type.
	 *
	 * @param protocol string protocol name
	 * @return new {@link FSRLRoot} instance.
	 */
	public static FSRLRoot makeRoot(String protocol) {
		return new FSRLRoot(null, protocol);
	}

	/**
	 * Creates a {@link FSRLRoot} as a child of a container {@link FSRL}, using the supplied
	 * {@code protocol} string as its type.
	 *
	 * @param containerFile {@link FSRL} of the container that contains this nested filesystem.
	 * @param fstype the filesystem type.
	 * @return new {@link FSRLRoot} instance with a parent pointing to the specified containerFile.
	 */
	public static FSRLRoot nestedFS(FSRL containerFile, String fstype) {
		if (containerFile instanceof FSRLRoot) {
			throw new RuntimeException("Can't make nestedFS with FSRLRoot path: " + containerFile);
		}
		return new FSRLRoot(containerFile, fstype);
	}

	/**
	 * Create a copy of {@code copyFSRL}, but using a different {@code containerFile} parent.
	 * <p>
	 * (ie. re-parents copyFSRL so its parent is containerFile)
	 *
	 * @param containerFile {@link FSRL} of new parent
	 * @param copyFSRL {@link FSRLRoot} that will be copied and re-parented.
	 * @return new {@link FSRLRoot}
	 */
	public static FSRLRoot nestedFS(FSRL containerFile, FSRLRoot copyFSRL) {
		if (containerFile instanceof FSRLRoot) {
			throw new RuntimeException("Can't make nestedFS with FSRLRoot path: " + containerFile);
		}
		return new FSRLRoot(containerFile, copyFSRL.getProtocol());
	}

	/**
	 * Cached hashcode.  There should be relatively few instances of FSRLRoot objects in
	 * memory (1 per active filesystem) so this has little memory impact.
	 */
	private final int hashCode;

	/**
	 * Private constructor used by static factory methods.
	 * <p>
	 * @param parent {@link FSRL} parent
	 * @param protocol string filesystem type.
	 */
	private FSRLRoot(FSRL parent, String protocol) {
		super(parent, protocol);
		this.hashCode = super.hashCode();
	}

	@Override
	public FSRLRoot getFS() {
		return this;
	}

	/**
	 * Returns the "protocol" portion of this FSRLRoot, for example, in a FSRLRoot of
	 * "file://", this method would return "file".
	 * <p>
	 * @return string protocol / filesystem type.
	 */
	public String getProtocol() {
		return path;
	}

	/**
	 * Returns the parent containerfile FSRL, or null if this FSRLRoot specifies
	 * a root-level filesystem.
	 * <p>
	 * @return {@link FSRL} of the container object that this filesystem is nested under.
	 */
	public FSRL getContainer() {
		return parent;
	}

	/**
	 * Returns true if there is a parent containerfile, or false if this FSRLRoot specifies
	 * a root-level filesystem.
	 *
	 * @return boolean true if this {@link FSRLRoot} has a parent container, or false if not.
	 */
	public boolean hasContainer() {
		return parent != null;
	}

	/**
	 * Always returns null for a FSRLRoot.
	 *
	 * @return null because this is a {@link FSRLRoot} instance which never has paths.
	 */
	@Override
	public String getPath() {
		return null;
	}

	/**
	 * Always returns null for a FSRLRoot.
	 *
	 * @return null because this is a {@link FSRLRoot} instance which never has a path and
	 * therefore doesn't have a name part of a path.
	 */
	@Override
	public String getName() {
		return null;
	}

	/**
	 * Creates a new {@link FSRL} as a child of this {@link FSRLRoot}, using the supplied
	 * path and MD5 values.
	 * <p>
	 * @param newPath string path and filename of the object inside this filesystem, should
	 * not be null.
	 * @param newMD5 string md5 of the object inside this filesystem, null ok.
	 * @return new {@link FSRL} instance which is a child of this {@link FSRLRoot}.
	 */
	public FSRL withPathMD5(String newPath, String newMD5) {
		return new FSRL(this, newPath, newMD5);
	}

	@Override
	protected void appendToStringBuilder(StringBuilder sb, boolean recurse, boolean includeParams,
			boolean includeFSRoot) {
		if (parent != null && recurse) {
			parent.appendToStringBuilder(sb, recurse, includeParams, includeFSRoot);
			sb.append("|");
		}
		if (includeFSRoot) {
			sb.append(path).append("://");
		}
	}

	@Override
	public int hashCode() {
		return hashCode;
	}
}
