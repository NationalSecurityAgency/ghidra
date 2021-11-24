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
package ghidra.file.formats.android.oat.bundle;

import java.util.List;

import ghidra.file.formats.android.art.ArtHeader;
import ghidra.file.formats.android.dex.format.DexHeader;
import ghidra.file.formats.android.oat.OatHeader;
import ghidra.file.formats.android.vdex.VdexHeader;

/**
 * A fictitious class to locate, open, and store all of the files
 * related to Android OAT/ART.
 */
public interface OatBundle {

	public enum HeaderType {
		ART, CDEX, DEX, VDEX,
	};

	public static final String APK = ".apk";
	public static final String ART = ".art";
	public static final String CLASSES = "classes";
	public static final String CDEX = "cdex";
	public static final String DEX = ".dex";
	public static final String JAR = ".jar";
	public static final String OAT = ".oat";
	public static final String ODEX = ".odex";
	public static final String VDEX = ".vdex";

	/**
	 * Closes the bundle and release any resources.
	 */
	public void close();

	/**
	 * Returns the corresponding OAT header.
	 * @return the corresponding OAT header.
	 */
	public OatHeader getOatHeader();

	/**
	 * Returns the corresponding ART header.
	 * @return the corresponding ART header.
	 */
	public ArtHeader getArtHeader();

	/**
	 * Returns the corresponding OAT header.
	 * @return the corresponding OAT header.
	 */
	public VdexHeader getVdexHeader();

	/**
	 * Returns the corresponding DEX headers.
	 * @return the corresponding DEX headers.
	 */
	public List<DexHeader> getDexHeaders();

	/**
	 * Returns the DEX header with the specified checksum.
	 * @return the DEX header with the specified checksum.
	 */
	public DexHeader getDexHeaderByChecksum(int checksum);

}
