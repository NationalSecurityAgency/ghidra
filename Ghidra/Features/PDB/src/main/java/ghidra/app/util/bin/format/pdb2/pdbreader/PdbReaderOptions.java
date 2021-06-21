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
package ghidra.app.util.bin.format.pdb2.pdbreader;

import java.nio.charset.Charset;
import java.util.List;

import ghidra.framework.options.Options;
import ghidra.program.model.data.CharsetInfo;
import ghidra.util.HelpLocation;

/**
 * Options used while reading a PDB ({@link AbstractPdb}) that control various aspects.  These
 * can be optional values used during our development of this PdbReader.  Currently included are
 * a field to control debug logging and {@link Charset} values used for String interpretation.
 */
public class PdbReaderOptions extends Exception {

	// Developer turn on/off options that are in still in development.
	private static final boolean developerMode = false;

	// Sets the one-byte Charset to be used for PDB processing.
	//  NOTE: This "Option" is not intended as a permanent part of this analyzer.  Should be
	//  replaced by target-specific Charset.
	private static final String OPTION_NAME_ONE_BYTE_CHARSET_NAME = "PDB One-Byte Charset Name";
	private static final String OPTION_DESCRIPTION_ONE_BYTE_CHARSET_NAME =
		"Charset used for processing of one-byte (or multi) encoded Strings: " +
			PdbReaderOptions.getOneByteCharsetNames();
	private static final String DEFAULT_ONE_BYTE_CHARSET_NAME = CharsetInfo.UTF8;
	private String oneByteCharsetName;

	// Sets the wchar_t Charset to be used for PDB processing.
	//  NOTE: This "Option" is not intended as a permanent part of this analyzer.  Should be
	//  replaced by target-program-specific Charset.
	private static final String OPTION_NAME_WCHAR_CHARSET_NAME = "PDB Wchar_t Charset Name";
	private static final String OPTION_DESCRIPTION_WCHAR_CHARSET_NAME =
		"Charset used for processing of wchar_t encoded Strings: " +
			PdbReaderOptions.getTwoByteCharsetNames();
	private static final String DEFAULT_TWO_BYTE_CHARSET_NAME = CharsetInfo.UTF16;
	private String wideCharCharsetName;

	//==============================================================================================
	private static List<String> oneByteCharsetNames =
		CharsetInfo.getInstance().getCharsetNamesWithCharSize(1);
	private static List<String> twoByteCharsetNames =
		CharsetInfo.getInstance().getCharsetNamesWithCharSize(2);

	private Charset oneByteCharset;
	private Charset wideCharset;

	/**
	 * Constructor.
	 */
	public PdbReaderOptions() {
		setDefaults();
	}

	public void registerOptions(Options options) {
		HelpLocation help = null;

		if (developerMode) {
			options.registerOption(OPTION_NAME_ONE_BYTE_CHARSET_NAME, oneByteCharsetName, help,
				OPTION_DESCRIPTION_ONE_BYTE_CHARSET_NAME);
			options.registerOption(OPTION_NAME_WCHAR_CHARSET_NAME, wideCharCharsetName, help,
				OPTION_DESCRIPTION_WCHAR_CHARSET_NAME);
		}
	}

	public void loadOptions(Options options) {

		if (developerMode) {
			oneByteCharsetName =
				options.getString(OPTION_NAME_ONE_BYTE_CHARSET_NAME, oneByteCharsetName);
			setOneByteCharsetForName(oneByteCharsetName);
			wideCharCharsetName =
				options.getString(OPTION_NAME_WCHAR_CHARSET_NAME, wideCharCharsetName);
			setWideCharCharsetForName(wideCharCharsetName);
		}
	}

	/**
	 * Set the options to their default values
	 */
	public void setDefaults() {
		oneByteCharsetName = DEFAULT_ONE_BYTE_CHARSET_NAME;
		wideCharCharsetName = DEFAULT_TWO_BYTE_CHARSET_NAME;
		setOneByteCharsetForName(oneByteCharsetName);
		setWideCharCharsetForName(wideCharCharsetName);
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
	 * @return this, so options can be daisy-chained.
	 */
	public PdbReaderOptions setOneByteCharsetForName(String name) {
		if (!oneByteCharsetNames.contains(name)) {
			throw new IllegalArgumentException("Unknown OneByteCharset: " + name);
		}
		oneByteCharset = Charset.forName(name);
		oneByteCharsetName = name;
		return this;
	}

	/**
	 * Sets the Wchar Charset to use for PDB processing.
	 * @param name Name of the Charset to use.
	 * @return this, so options can be daisy-chained.
	 */
	public PdbReaderOptions setWideCharCharsetForName(String name) {
		if (!twoByteCharsetNames.contains(name)) {
			throw new IllegalArgumentException("Unknown TwoByteCharset: " + name);
		}
		wideCharset = Charset.forName(name);
		wideCharCharsetName = name;
		return this;
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
		return wideCharCharsetName;
	}

	/**
	 * Returns the name of the Wchar Charset in use for PDB processing.
	 * @return the name of the Wchar Charset.
	 */
	public String getWideCharCharsetName() {
		return wideCharCharsetName;
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
		return wideCharset;
	}

	/**
	 * Returns the Wchar Charset in use for PDB processing.
	 * @return the Wchar Charset.
	 */
	public Charset getWideCharCharset() {
		return wideCharset;
	}
}
