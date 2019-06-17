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
package ghidra.pdb.pdbreader;

import java.nio.charset.Charset;
import java.util.List;

import ghidra.program.model.data.CharsetInfo;

/**
 * Options used while reading a PDB ({@link AbstractPdb}) that control various aspects.  These
 * can be optional values used during our development of this PdbReader.  Currently included are
 * a field to control debug logging and {@link Charset} values used for String interpretation.
 */
public class PdbReaderOptions extends Exception {

	private static final String DEFAULT_ONE_BYTE_CHARSET_NAME = CharsetInfo.UTF8;
	private static final String DEFAULT_TWO_BYTE_CHARSET_NAME = CharsetInfo.UTF16;

	private static List<String> oneByteCharsetNames =
		CharsetInfo.getInstance().getCharsetNamesWithCharSize(1);
	private static List<String> twoByteCharsetNames =
		CharsetInfo.getInstance().getCharsetNamesWithCharSize(2);

	private String oneByteCharsetName;
	private String twoByteCharsetName;

	private Charset oneByteCharset;
	private Charset twoByteCharset;

	private boolean debug;

	/**
	 * Constructor.
	 */
	public PdbReaderOptions() {
		oneByteCharsetName = DEFAULT_ONE_BYTE_CHARSET_NAME;
		twoByteCharsetName = DEFAULT_TWO_BYTE_CHARSET_NAME;
		setOneByteCharsetForName(oneByteCharsetName);
		setWideCharCharsetForName(twoByteCharsetName);
	}

	/**
	 * Returns list of Charsets names that encode one byte characters.
	 * @return Charsets that encode one byte characters.
	 */
	public static List<String> getOneByteCharsetNames() {
		return oneByteCharsetNames;
	}

	/**
	 * Returns list of Charsets names that encode two byte characters.
	 * @return Charsets that encode two byte characters.
	 */
	public static List<String> getTwoByteCharsetNames() {
		return twoByteCharsetNames;
	}

	/**
	 * Sets the one-byte Charset to use for PDB processing.
	 * @param name Name of the Charset to use.
	 * @return {@code true} if was able to set the Charset.
	 */
	public boolean setOneByteCharsetForName(String name) {
		if (!oneByteCharsetNames.contains(name)) {
			return false;
		}
		oneByteCharset = Charset.forName(name);
		oneByteCharsetName = name;
		return true;
	}

	/**
	 * Sets the Wchar Charset to use for PDB processing.
	 * @param name Name of the Charset to use.
	 * @return {@code true} if was able to set the Charset.
	 */
	public boolean setWideCharCharsetForName(String name) {
		if (!twoByteCharsetNames.contains(name)) {
			return false;
		}
		twoByteCharset = Charset.forName(name);
		twoByteCharsetName = name;
		return true;
	}

	/**
	 * Returns the name of the one-byte Charset in use for PDB processing.
	 * @return the name of the Charset.
	 */
	public String getOneByteCharsetName() {
		return oneByteCharsetName;
	}

	/**
	 * Returns the name of the two-byte Charset in use for PDB processing.
	 * @return the name of the Charset.
	 */
	public String getTwoByteCharsetName() {
		return twoByteCharsetName;
	}

	/**
	 * Returns the one-byte Charset in use for PDB processing.
	 * @return the Charset.
	 */
	public Charset getOneByteCharset() {
		return oneByteCharset;
	}

	/**
	 * Returns the two-byte Charset in use for PDB processing.
	 * @return the Charset.
	 */
	public Charset getTwoByteCharset() {
		return twoByteCharset;
	}

	/**
	 * Enable/disable developmental debug.
	 * @param debug {@code true} to turn debug on; default is {@code false}.
	 */
	public void setDebug(boolean debug) {
		this.debug = debug;
	}

	/**
	 * Returns true if debug is "on."
	 * @return {@code true} if debug is "on."
	 */
	public boolean isDebug() {
		return debug;
	}

}
