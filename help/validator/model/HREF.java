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
package help.validator.model;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Path;

import help.HelpBuildUtils;
import help.validator.location.HelpModuleLocation;

public class HREF implements Comparable<HREF> {

	private HelpModuleLocation help;
	private final Path sourceFile;

	private Path refFile;
	private String anchorName;
	private final int lineNumber;
	private final String href;
	private final boolean isRemote;
	private boolean isLocalAnchor;
	private Path relativePath;

	public HREF(HelpModuleLocation help, Path sourceFile, String href, int lineNum)
			throws URISyntaxException {
		this.help = help;
		this.sourceFile = sourceFile;
		this.href = href;
		this.lineNumber = lineNum;

		URI resolved;
		if (href.startsWith("help/topics")) {
			resolved = new URI(href);
		}
		else {
			URI URI = sourceFile.toUri();
			resolved = URI.resolve(href);
		}

		isRemote = HelpBuildUtils.isRemote(resolved);
		if (!isRemote) {
			if (resolved.getFragment() == null) {
				this.refFile = HelpBuildUtils.locateReference(sourceFile, href);
				this.anchorName = null;
			}
			else if (resolved.getPath() == null) {
				// HREF to local anchor
				this.refFile = sourceFile;
				this.anchorName = resolved.getFragment();
				this.isLocalAnchor = true;
			}
			else {
				// HREF to other file
				this.refFile = HelpBuildUtils.locateReference(sourceFile, href);
				this.anchorName = resolved.getFragment();
			}
		}

		this.relativePath = HelpBuildUtils.relativizeWithHelpTopics(refFile);
	}

	public boolean isURL() {
		return isRemote;
	}

	public boolean isLocalAnchor() {
		return isLocalAnchor;
	}

	public Path getSourceFile() {
		return sourceFile;
	}

	public boolean isRemote() {
		return isRemote;
	}

	public String getAnchorName() {
		return anchorName;
	}

	public String getRefString() {
		return href;
	}

	/** The relative help path to the destination of this HREF */
	public Path getReferenceFileHelpPath() {
		return relativePath;
	}

	public String getHelpPath() {
		Path referenceFileHelpPath = getReferenceFileHelpPath();
		if (referenceFileHelpPath == null) {
			return null;
		}
		if (anchorName == null) {
			return referenceFileHelpPath.toString();
		}

		return referenceFileHelpPath.toString() + '#' + anchorName;
	}

	@Override
	public int compareTo(HREF other) {
		if (this.equals(other)) {
			return 0;
		}

		// group all HREFs in the same directory first
		HelpModuleLocation otherHelp = other.help;
		Path otherHelpLoc = otherHelp.getHelpLocation();
		Path myHelpLoc = help.getHelpLocation();
		if (!myHelpLoc.equals(otherHelpLoc)) {
			return myHelpLoc.compareTo(otherHelpLoc);
		}

		// check file
		Path otherSourceFile = other.getSourceFile();
		if (!sourceFile.equals(otherSourceFile)) {
			return sourceFile.compareTo(otherSourceFile);
		}

		// same source file, check line number
		if (lineNumber != other.lineNumber) {
			return lineNumber - other.lineNumber;
		}

		String helpPath = getHelpPath();
		String otherHelpPath = other.getHelpPath();
		if (helpPath != null && otherHelpPath != null) {
			int result = helpPath.compareTo(otherHelpPath);
			if (result != 0) {
				return result;
			}
		}
		else {
			if (helpPath == null && otherHelpPath != null) {
				return -1; // our path is null and 'other's is not; we go before
			}
			else if (helpPath != null && otherHelpPath == null) {
				return 1; // we have a non-null path, but 'other' doesn't; we go after
			}
		}

		// highly unlikely case that we have to HREFs from the same file, pointing to the same
		// place, on the same HTML line.  In this case, just use the object that was created first,
		// as it was probably parsed first from the file
		int identityHashCode = System.identityHashCode(this);
		int otherIdentityHashCode = System.identityHashCode(other);
		return identityHashCode - otherIdentityHashCode;
	}

	@Override
	public String toString() {

		String source = null;
		Path sourcePath = HelpBuildUtils.relativizeWithHelpTopics(sourceFile);
		if (sourcePath == null) {
			// not in 'help/topics'; relativize to the repo name
			Path repoRoot = help.getModuleRepoRoot();
			Path name = repoRoot.getFileName();
			sourcePath = HelpBuildUtils.relativize(name, sourceFile);
		}

		source = sourcePath.toString();
		//@formatter:off
		return "<a href=\"" + href + "\">\n\t\t\t" +
					"From: " + source + " (line:" + lineNumber + "),\n\t\t\t" +
					"Resolved to: " + refFile;
		//@formatter:on
	}

	public int getLineNumber() {
		return lineNumber;
	}
}
