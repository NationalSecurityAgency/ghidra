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
package generic.theme;

import java.io.*;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.apache.commons.io.FileUtils;

import ghidra.framework.Application;
import ghidra.util.Msg;

public class ExternalThemeReader extends ThemeReader {

	public ExternalThemeReader(File file) throws IOException {
		try (ZipFile zipFile = new ZipFile(file)) {
			Enumeration<? extends ZipEntry> entries = zipFile.entries();
			while (entries.hasMoreElements()) {
				ZipEntry entry = entries.nextElement();
				String name = entry.getName();
				try (InputStream is = zipFile.getInputStream(entry)) {
					if (name.endsWith(".theme")) {
						processThemeData(name, is);
					}
					else {
						processIconFile(name, is);
					}
				}
			}
		}
	}

	private void processIconFile(String path, InputStream is) throws IOException {
		int indexOf = path.indexOf("images/");
		if (indexOf < 0) {
			Msg.error(this, "Unknown file: " + path);
		}
		String relativePath = path.substring(indexOf, path.length());
		File dir = Application.getUserSettingsDirectory();
		File iconFile = new File(dir, relativePath);
		FileUtils.copyInputStreamToFile(is, iconFile);
	}

	private void processThemeData(String name, InputStream is) throws IOException {
		InputStreamReader reader = new InputStreamReader(is);
		read(reader);
	}
}
