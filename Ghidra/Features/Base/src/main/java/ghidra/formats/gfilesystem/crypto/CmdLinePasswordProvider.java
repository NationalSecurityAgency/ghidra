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
package ghidra.formats.gfilesystem.crypto;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.*;

import org.apache.commons.io.FilenameUtils;

import ghidra.formats.gfilesystem.FSRL;
import ghidra.util.Msg;
import utilities.util.FileUtilities;

/**
 * A {@link PasswordProvider} that supplies passwords to decrypt files via the java jvm invocation.
 * <p>
 * Example: <pre>java -Dfilesystem.passwords=/fullpath/to/textfile</pre>
 * <p>
 * The password file is a plain text tabbed-csv file, where each line
 * specifies a password and an optional file identifier.
 * <p>
 * Example file contents, where each line is divided into fields by a tab
 * character where the first field is the password and the second optional field
 * is the file's identifying information (name, path, etc):
 * <p>
 * <pre>
 * <code>password1   [tab]   myfirstzipfile.zip</code> <b>&larr; supplies a password for the named file located in any directory</b>
 * <code>someOtherPassword   [tab]   /full/path/tozipfile.zip</code> <b>&larr; supplies password for file at specified location</b> 
 * <code>anotherPassword [tab]   file:///full/path/tozipfile.zip|zip:///subdir/in/zip/somefile.txt</code> <b>&larr; supplies password for file embedded inside a zip</b>
 * <code>yetAnotherPassword</code> <b>&larr; a password to try for any file that needs a password</b>
 * </pre>
 * 
 * 
 */
public class CmdLinePasswordProvider implements PasswordProvider {
	public static final String CMDLINE_PASSWORD_PROVIDER_PROPERTY_NAME = "filesystem.passwords";

	@Override
	public Iterator<PasswordValue> getPasswordsFor(FSRL fsrl, String prompt, Session session) {
		String propertyValue = System.getProperty(CMDLINE_PASSWORD_PROVIDER_PROPERTY_NAME);
		if (propertyValue == null) {
			return Collections.emptyIterator();
		}
		File passwordFile = new File(propertyValue);
		return load(passwordFile, fsrl).iterator();
	}

	private List<PasswordValue> load(File f, FSRL fsrl) {
		List<PasswordValue> result = new ArrayList<>();
		try {
			for (String s : FileUtilities.getLines(f)) {
				String[] fields = s.split("\t");
				String password = fields[0];
				if (password.isBlank()) {
					continue;
				}
				String fileIdStr = fields.length > 1 ? fields[1] : null;

				if (fileIdStr == null) {
					// no file identifier string, always matches
					result.add(PasswordValue.wrap(password.toCharArray()));
					continue;
				}

				// try to match the name string as a FSRL, a path or a plain name.
				try {
					FSRL currentFSRL = FSRL.fromString(fileIdStr);
					// was a fsrl string, only test as fsrl
					if (currentFSRL.isEquivalent(fsrl)) {
						result.add(PasswordValue.wrap(password.toCharArray()));
					}
					continue;
				}
				catch (MalformedURLException e) {
					// ignore
				}
				String nameOnly = FilenameUtils.getName(fileIdStr);
				if (!nameOnly.equals(fileIdStr)) {
					// was a path str, only test against path component
					if (fileIdStr.equals(fsrl.getPath())) {
						result.add(PasswordValue.wrap(password.toCharArray()));
					}
					continue;
				}

				// was a plain name, only test against name component
				if (nameOnly.equals(fsrl.getName())) {
					result.add(PasswordValue.wrap(password.toCharArray()));
					continue;
				}
				// no matches, try next line
			}
		}
		catch (IOException e) {
			Msg.warn(this, "Error reading passwords from file: " + f, e);
		}

		return result;
	}
}
