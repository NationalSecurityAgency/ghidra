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
package docking.widgets.table.model;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import resources.ResourceManager;
import utilities.util.FileUtilities;

public class DirData {
	private String date;
	private String time;
	private boolean isDir;
	private String name;
	private Integer size;

	public static List<DirData> loadTestData(String file) throws IOException {
		try (InputStream is = ResourceManager.getResourceAsStream(file)) {
			List<String> lines = FileUtilities.getLines(is);
			List<DirData> data = new ArrayList<>();
			for (String line : lines) {
				data.add(new DirData(line));
			}
			return data;
		}
	}

	public String getDate() {
		return date;
	}

	public String getTime() {
		return time;
	}

	public boolean isDir() {
		return isDir;
	}

	public String getName() {
		return name;
	}

	public Integer getSize() {
		return size;
	}

	public DirData(String line) {
		StringTokenizer nizer = new StringTokenizer(line);
		date = nizer.nextToken();
		time = nizer.nextToken();
		String dir = nizer.nextToken();
		boolean isDirectory = dir.toLowerCase().equals("<dir>");

		if (!isDirectory) {
			String numStr = "";
			for (int i = 0; i < dir.length(); i++) {
				if (dir.charAt(i) != ',') {
					numStr += dir.charAt(i);
				}
			}
			size = new Integer(numStr);
		}

		name = nizer.nextToken();
	}
}
