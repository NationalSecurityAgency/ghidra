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

import java.net.URISyntaxException;
import java.nio.file.Path;

import help.HelpBuildUtils;
import help.ImageLocation;
import help.validator.location.HelpModuleLocation;

public class IMG implements Comparable<IMG> {

	private HelpModuleLocation help;
	private final Path sourceFile;
	/** Relative--starting with help/topics */
	private final Path relativePath;
	private final String imgSrc;

	/**
	 * The file on this filesystem; null if the file does not exists or of the image src 
	 * points to a remote URL or a runtime url.
	 * <P>
	 * An example remote URL is one that points to a web server, like <code>http://...</code>
	 * <BR>An example runtime URL is one that the help system knows how to resolve at 
	 * runtime, like <code>&lt;IMG SRC='Icons.REFRESH_ICON /'&gt;</code>
	 */
	private final Path imgFile;
	private final ImageLocation imageLocation;
	private final int lineNumber;

	/**
	 * Constructor 
	 * 
	 * @param help the help module containing the file containing this IMG reference
	 * @param sourceFile the source file containing this IMG reference
	 * @param imgSrc the IMG SRC attribute pulled from the HTML file
	 * @param lineNumber the line number of the IMG tag
	 * @throws URISyntaxException
	 */
	public IMG(HelpModuleLocation help, Path sourceFile, String imgSrc, int lineNumber)
			throws URISyntaxException {
		this.help = help;
		this.sourceFile = sourceFile;
		this.relativePath = HelpBuildUtils.relativizeWithHelpTopics(sourceFile);
		this.imgSrc = imgSrc;
		this.lineNumber = lineNumber;

		this.imageLocation = HelpBuildUtils.locateImageReference(sourceFile, imgSrc);
		this.imgFile = imageLocation.getResolvedPath();
	}

	public Path getSourceFile() {
		return sourceFile;
	}

	public String getSrcAttribute() {
		return imgSrc;
	}

	public boolean isRemote() {
		return imageLocation.isRemote();
	}

	public boolean isRuntime() {
		return imageLocation.isRuntime();
	}

	public boolean isInvalid() {
		return imageLocation.isInvalidRuntimeImage();
	}

	public Path getImageFile() {
		return imgFile;
	}

	public Path getHelpPath() {
		return imgFile;
	}

	public int getLineNumber() {
		return lineNumber;
	}

	@Override
	public int compareTo(IMG other) {

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
			return sourceFile.toUri().compareTo(otherSourceFile.toUri());
		}

		// same source file, check line number
		if (lineNumber != other.lineNumber) {
			return lineNumber - other.lineNumber;
		}

		Path myHelpPath = getHelpPath();
		Path otherHelpPath = other.getHelpPath();
		if (myHelpPath != null && otherHelpPath != null) {
			int result = myHelpPath.compareTo(otherHelpPath);
			if (result != 0) {
				return result;
			}
		}
		else {
			if (myHelpPath == null && otherHelpPath != null) {
				return -1; // our path is null and 'other's is not; we go before
			}
			else if (myHelpPath != null && otherHelpPath == null) {
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
		return "<img src=\"" + imgSrc + "\">  [\n\t\tFrom: " + relativePath + ",\n\t\tResolved: " +
			imgFile + "\n\t]";
	}
}
