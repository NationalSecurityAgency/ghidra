/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package help.validator.links;

import help.validator.model.IMG;

import java.nio.file.Path;

public class InvalidIMGLink implements InvalidLink {

	protected final IMG img;
	protected final String message;

	protected InvalidIMGLink(IMG img, String message) {
		this.img = img;
		this.message = message;
		if (Boolean.parseBoolean(System.getProperty("ghidra.help.failfast"))) {
			throw new RuntimeException(message + ": " + img);
		}
	}

	public IMG getIMG() {
		return img;
	}

	@Override
	public int identityHashCode() {
		return System.identityHashCode(img);
	}

	@Override
	public int getLineNumber() {
		return img.getLineNumber();
	}

	@Override
	public Path getSourceFile() {
		return img.getSourceFile();
	}

	@Override
	public int compareTo(InvalidLink other) {
		if (other == null) {
			return 1;
		}

		if (!(other instanceof InvalidIMGLink)) {
			return 1;
		}
		InvalidIMGLink otherLink = (InvalidIMGLink) other;

		// Artificial sorting priority based upon the type of invalid link.  When I wrote this, it
		// turns out that reverse alphabetical order is what I want, which is something like
		// missing files first, missing anchors in files second followed by illegal associations
		String className = getClass().getSimpleName();
		String otherClassName = other.getClass().getSimpleName();
		int result = className.compareTo(otherClassName);
		if (result != 0) {
			return -result;
		}

		return img.compareTo(otherLink.img);
	}

	@Override
	public String toString() {
		return message + " -\n\tlink: " + img + "\n\tfrom file: " + getSourceFileInfo();
	}

	private String getSourceFileInfo() {
		int lineNumber = img.getLineNumber();
		return img.getSourceFile().toUri() + " (line:" + lineNumber + ")";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((img == null) ? 0 : img.hashCode());
		result = prime * result + ((message == null) ? 0 : message.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		InvalidIMGLink other = (InvalidIMGLink) obj;
		if (img == null) {
			if (other.img != null)
				return false;
		}
		else if (!img.equals(other.img))
			return false;
		if (message == null) {
			if (other.message != null)
				return false;
		}
		else if (!message.equals(other.message))
			return false;
		return true;
	}
}
