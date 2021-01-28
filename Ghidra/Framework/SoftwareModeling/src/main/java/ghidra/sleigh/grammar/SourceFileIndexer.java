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
package ghidra.sleigh.grammar;

import java.io.PrintStream;

import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;

import ghidra.pcodeCPort.utils.XmlUtils;
import ghidra.util.Msg;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * This class is used to index source files in a SLEIGH language module.
 * The SLEIGH compiler records the index of the source file for a constructor rather
 * than the file name.  This is an optimization to avoid repeating the file name in
 * the .sla files.  
 */
public class SourceFileIndexer {

	private BiMap<String, Integer> filenameToIndex;
	private int leastUnusedIndex;

	/**
	 * Creates a {code SourceFileIndexer} object with an empty index.
	 */
	public SourceFileIndexer() {
		filenameToIndex = HashBiMap.create();
		leastUnusedIndex = 0;
	}

	/**
	 * Adds the filename of a location to the index if it is not already present.
	 * @param loc location containing filename to add
	 * @return index associated with filename, or {@code null} if a {@code null} {@link Location}
	 * or a {@link Location} with a {@code null} filename was provided as input.
	 */
	public Integer index(Location loc) {
		if (loc == null) {
			Msg.info(this, "null Location");
			return null;
		}
		String filename = loc.filename;
		if (filename == null) {
			Msg.info(this, "null filename");
			return null;
		}
		Integer res = filenameToIndex.putIfAbsent(filename, leastUnusedIndex);
		if (res == null) {
			return leastUnusedIndex++;
		}
		return res;
	}

	/**
	 * Returns the index for a filename
	 * @param filename file
	 * @return index or {@code null} if {@code filename} is not in the index.
	 */
	public Integer getIndex(String filename) {
		return filenameToIndex.get(filename);
	}

	/**
	 * Returns the file name at a given index
	 * @param index index
	 * @return file name or {@code null} if there is no file with that index
	 */
	public String getFileName(Integer index) {
		return filenameToIndex.inverse().get(index);
	}

	/**
	 * Save the index as XML 
	 * @param s stream to write to
	 */
	public void saveXml(PrintStream s) {
		s.append("<sourcefiles>\n");
		for (int i = 0; i < leastUnusedIndex; ++i) {
			s.append("<sourcefile name=\"");
			XmlUtils.xml_escape(s, filenameToIndex.inverse().get(i));
			s.append("\" index=\"" + i + "\"/>\n");
		}
		s.append("</sourcefiles>\n");
	}

	/**
	 * Restore an index saved as to XML
	 * @param parser xml parser
	 */
	public void restoreXml(XmlPullParser parser) {
		XmlElement elem = parser.start("sourcefiles");
		XmlElement subElem = null;
		while ((subElem = parser.softStart("sourcefile")) != null) {
			String filename = subElem.getAttribute("name");
			Integer index = Integer.parseInt(subElem.getAttribute("index"));
			filenameToIndex.put(filename, index);
			parser.end(subElem);
		}
		parser.end(elem);
	}

}
