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
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import com.google.common.io.Files;

public class ZipGTheme extends FileGTheme {

	public ZipGTheme(File file, String name, LafType laf, boolean useDarkDefaults) {
		super(file, name, laf, useDarkDefaults);
	}

	public ZipGTheme(File file) throws IOException {
		this(file, new ExternalThemeReader(file));
	}

	public ZipGTheme(File file, ThemeReader reader) {
		super(file, reader.getThemeName(), reader.getLookAndFeelType(), reader.useDarkDefaults());
		reader.loadValues(this);
	}

	@Override
	public void save() throws IOException {
		String dir = getName() + ".theme/";
		try (FileOutputStream fos = new FileOutputStream(file)) {
			ZipOutputStream zos = new ZipOutputStream(fos);
			saveThemeFileToZip(dir, zos);
			Set<File> iconFiles = getExternalIconFiles();
			for (File iconFile : iconFiles) {
				copyToZipFile(dir, iconFile, zos);
			}
			zos.finish();
		}
	}

	private void copyToZipFile(String dir, File iconFile, ZipOutputStream zos) throws IOException {
		ZipEntry entry = new ZipEntry(dir + "images/" + iconFile.getName());
		zos.putNextEntry(entry);
		Files.copy(iconFile, zos);
	}

	private void saveThemeFileToZip(String dir, ZipOutputStream zos) throws IOException {
		ZipEntry entry = new ZipEntry(dir + getName() + ".theme");
		zos.putNextEntry(entry);
		BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(zos));
		writeThemeValues(writer);
		writer.flush();
	}

}
