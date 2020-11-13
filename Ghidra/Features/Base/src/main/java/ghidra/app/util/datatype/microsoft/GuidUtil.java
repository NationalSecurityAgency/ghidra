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
package ghidra.app.util.datatype.microsoft;

import java.io.*;
import java.util.Hashtable;

import generic.jar.ResourceFile;
import ghidra.docking.settings.SettingsImpl;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.*;

public class GuidUtil {

	public enum GuidType {

		CLSID("clsids.txt", false),
		IID("iids.txt", false),
		GUID("guids.txt", false),
		SYNTAX("syntaxes.txt", true);

		private String filename;
		private boolean hasVersion;

		GuidType(String filename, boolean hasVersion) {
			this.filename = filename;
			this.hasVersion = hasVersion;
		}

		public String getFilename() {
			return filename;
		}

		public boolean hasVersion() {
			return hasVersion;
		}
	}

	private static String ARCHIVE_DIR = "msvcrt";
	private static String ARCHIVE_DIR_PARENT = "typeinfo/win32";
	private static boolean initialized = false;
	private static GuidType[] guidTypes = new GuidType[] { GuidType.CLSID, GuidType.IID,
		GuidType.GUID, GuidType.SYNTAX };
	private static Hashtable<GuidType, Hashtable<String, GuidInfo>> idTables;

	private final static void initialize() {
		if (initialized) {
			return;
		}
		idTables = new Hashtable<GuidType, Hashtable<String, GuidInfo>>();
		for (GuidType guidType : guidTypes) {
			idTables.put(guidType, new Hashtable<String, GuidInfo>());
		}
		buildGuidMap();
		initialized = true;
	}

	public static GuidInfo getKnownGuid(Program program, Address address) {
		String guidString = GuidUtil.getGuidString(program, address, false);
		return getKnownGuid(guidString);
	}

	public static GuidInfo getKnownGuid(String guidString) {
		if (guidString == null) {
			return null;
		}
		initialize();
		guidString = guidString.toUpperCase();
		for (GuidType guidType : guidTypes) {
			if (guidType.equals(GuidType.SYNTAX)) {
				continue;
			}
			Hashtable<String, GuidInfo> table = idTables.get(guidType);
			GuidInfo guidInfo = table.get(guidString);
			if (guidInfo != null) {
				return guidInfo;
			}
		}
		return null;
	}

	public static GuidInfo getKnownVersionedGuid(String versionedGuidString) {
		initialize();
		versionedGuidString = versionedGuidString.toUpperCase();
		Hashtable<String, GuidInfo> table = idTables.get(GuidType.SYNTAX);
		GuidInfo guidInfo = table.get(versionedGuidString);
		if (guidInfo != null) {
			return guidInfo;
		}
		return null;
	}

	private static void buildGuidMap() {
		for (GuidType guidType : guidTypes) {
			Hashtable<String, GuidInfo> table = idTables.get(guidType);

			String filename = guidType.getFilename();
			readGuidFile(guidType, filename, table);
		}
	}

	private static void readGuidFile(GuidType guidType, String filename,
			Hashtable<String, GuidInfo> table) {
		try {
			ResourceFile dir =
				Application.getModuleDataSubDirectory(ARCHIVE_DIR_PARENT + "/" + ARCHIVE_DIR);
			ResourceFile infile = new ResourceFile(dir, filename);
			if (!infile.exists()) {
				Msg.error(GuidUtil.class, "ERROR: file not found: " + filename);
				return;
			}
			BufferedReader input =
				new BufferedReader(new InputStreamReader(infile.getInputStream()));

			String inline;
			while ((inline = input.readLine()) != null) {
				if (!inline.startsWith("#") && (inline.length() >= 30)) {
					GuidInfo guidInfo = parseLine(inline, "-", guidType);
					if (guidInfo != null) {
						table.put(guidInfo.getUniqueIdString(), guidInfo);
					}
				}
			}
			input.close();
		}
		catch (IOException e1) {
			Msg.error(GuidUtil.class, "Unexpected Exception: " + e1.getMessage(), e1);
		}
	}

	public static GuidInfo parseLine(String guidNameLine, String delim, GuidType guidType) {

		final int NUM_BYTES = 16;
		long[] data = new long[4];
		String version = null;
		String name;

		boolean hasVersion = guidType.hasVersion();
		guidNameLine = guidNameLine.replaceAll("\t", " ");
		String guidString = guidNameLine.substring(0, guidNameLine.indexOf(" "));
		String strippedGUID = guidString.replaceAll(delim, "");
		if (strippedGUID.length() != NUM_BYTES * 2) {
			Msg.error(GuidUtil.class, "ERROR PARSING GUID: " + guidNameLine);
			return null;
		}
		data[0] = (0xFFFFFFFFL & NumericUtilities.parseHexLong(strippedGUID.substring(0, 8)));
		String str = strippedGUID.substring(8, 16);
		str = str.substring(4, 8) + str.substring(0, 4);
		data[1] = (0xFFFFFFFFL & NumericUtilities.parseHexLong(str));
		str = strippedGUID.substring(16, 24);
		str = str.substring(6, 8) + str.substring(4, 6) + str.substring(2, 4) + str.substring(0, 2);
		data[2] = (0xFFFFFFFFL & NumericUtilities.parseHexLong(str));
		str = strippedGUID.substring(24, 32);
		str = str.substring(6, 8) + str.substring(4, 6) + str.substring(2, 4) + str.substring(0, 2);
		data[3] = (0xFFFFFFFFL & NumericUtilities.parseHexLong(str));

		String left = guidNameLine.substring(36);
		if (hasVersion) {
			int vpos = left.indexOf("v");
			if (vpos > 0) {
				left = left.substring(vpos);
				int sppos = left.indexOf(" ");
				if (sppos > 0) {
					version = left.substring(0, sppos);
				}
				else {
					version = left.substring(0);
				}
				left = left.substring(version.length());
			}
		}
		name = left.substring(left.indexOf(" ") + 1);
		if (isOK(data)) {
			if (!hasVersion) {
				return new GuidInfo(guidString, name, guidType);
			}
			return new VersionedGuidInfo(guidString, version, name, guidType);
		}
		return null;
	}

	private static boolean isOK(long[] data) {
		for (long element : data) {
			if ((element != 0) || (element != 0xFFFFFFFFL)) {
				return true;
			}
		}
		return false;
	}

	public static String getGuidString(Program program, Address address, boolean validate) {

		String delim = "-";

		byte[] bytes = new byte[16];
		long[] data = new long[4];
		boolean isBigEndian = program.getMemory().isBigEndian();
		DataConverter conv = DataConverter.getInstance(isBigEndian);

		try {
			program.getMemory().getBytes(address, bytes);
			for (int i = 0; i < data.length; i++) {
				data[i] = 0xFFFFFFFFL & conv.getInt(bytes, i * 4);
				conv.getBytes((int) data[i], bytes, i * 4);
			}
		}
		catch (MemoryAccessException e) {
			return null; // TODO is this ok?
		}

		String guidString;
		guidString = Conv.toHexString((int) data[0]) + delim;
		guidString += Conv.toHexString((short) (data[1])) + delim;
		guidString += Conv.toHexString((short) (data[1] >> 16)) + delim;
		for (int i = 0; i < 4; i++) {
			guidString += Conv.toHexString((byte) (data[2] >> i * 8));
			if (i == 1) {
				guidString += delim;
			}
		}
		for (int i = 0; i < 4; i++) {
			guidString += Conv.toHexString((byte) (data[3] >> i * 8));
		}
		// retVal = retVal.toUpperCase();
		if (validate && !NewGuid.isOKForGUID(bytes, 0)) {
			return null;
		}

		return guidString;
	}

	public static String getVersionedGuidString(Program program, Address address, boolean validate) {

		String delim = "-";

		byte[] bytes = new byte[20];
		long[] data = new long[4];
		int[] versionData = new int[2];
		boolean isBigEndian = program.getMemory().isBigEndian();
		DataConverter conv = DataConverter.getInstance(isBigEndian);

		try {
			program.getMemory().getBytes(address, bytes);
			for (int i = 0; i < data.length; i++) {
				data[i] = 0xFFFFFFFFL & conv.getInt(bytes, i * 4);
				conv.getBytes((int) data[i], bytes, i * 4);
			}
		}
		catch (MemoryAccessException e) {
			return null; // TODO is this ok?
		}

		String guidString;
		guidString = Conv.toHexString((int) data[0]) + delim;
		guidString += Conv.toHexString((short) (data[1])) + delim;
		guidString += Conv.toHexString((short) (data[1] >> 16)) + delim;
		for (int i = 0; i < 4; i++) {
			guidString += Conv.toHexString((byte) (data[2] >> i * 8));
			if (i == 1) {
				guidString += delim;
			}
		}
		for (int i = 0; i < 4; i++) {
			guidString += Conv.toHexString((byte) (data[3] >> i * 8));
		}
		// retVal = retVal.toUpperCase();

		guidString += " v";
		versionData[0] = (bytes[17] << 8) + bytes[16];
		guidString += Integer.toString(versionData[0]) + ".";
		versionData[1] = (bytes[19] << 8) + bytes[18];
		guidString += Integer.toString(versionData[1]);

		if (validate && !NewGuid.isOKForGUID(bytes, 0)) {
			return null;
		}

		return guidString;
	}

	private static final String MS_GUID_PREFIX = "_GUID_";

	/**
	 * Verify that the specified label correpsonds to a Microsoft symbol name 
	 * for the GUID stored at the specified address within program.
	 * @param program program
	 * @param address memory address
	 * @param label symbol name to be checked
	 * @return true if label is a valid GUID label which corresponds to the GUID
	 * stored at address within program
	 */
	public static boolean isGuidLabel(Program program, Address address, String label) {
		if (!label.startsWith(MS_GUID_PREFIX)) {
			return false;
		}
		String guidString = label.substring(MS_GUID_PREFIX.length()).replace("_", "-");
		try {
			new GUID(guidString);
		}
		catch (Exception e) {
			return false;
		}
		GuidDataType dt = new GuidDataType();
		String guidRep = dt.getRepresentation(new DumbMemBufferImpl(program.getMemory(), address),
			new SettingsImpl(), -1);
		return guidRep.endsWith(guidString);
	}

}
