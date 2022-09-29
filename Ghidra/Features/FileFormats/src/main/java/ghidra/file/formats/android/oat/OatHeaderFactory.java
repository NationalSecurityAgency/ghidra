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
package ghidra.file.formats.android.oat;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.formats.android.oat.bundle.OatBundle;
import ghidra.file.formats.android.oat.bundle.OatBundleFactory;
import ghidra.file.formats.android.oat.headers.*;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public final class OatHeaderFactory {

	/**
	 * Returns an OatHeader of the correct version.
	 * @param reader the binary reader for the OAT header
	 * @return the new OAT header
	 * @throws IOException if OAT header cannot be created from reader
	 * @throws UnsupportedOatVersionException when the provided version is invalid or not yet implemented.
	 */
	public final static OatHeader newOatHeader(BinaryReader reader)
			throws IOException, UnsupportedOatVersionException {
		String magic = new String(reader.readByteArray(0, OatConstants.MAGIC.length()));
		String version = reader.readAsciiString(4, 4);
		if (magic.equals(OatConstants.MAGIC)) {
			if (OatConstants.isSupportedVersion(version)) {
				switch (version) {
					case OatConstants.OAT_VERSION_007:
						return new OatHeader_007(reader);
					case OatConstants.OAT_VERSION_039:
						return new OatHeader_039(reader);
					case OatConstants.OAT_VERSION_045:
						return new OatHeader_045(reader);
					case OatConstants.OAT_VERSION_051:
						return new OatHeader_051(reader);
					case OatConstants.OAT_VERSION_064:
						return new OatHeader_064(reader);
					case OatConstants.OAT_VERSION_079:
						return new OatHeader_079(reader);
					case OatConstants.OAT_VERSION_088:
						return new OatHeader_088(reader);
					case OatConstants.OAT_VERSION_124:
						return new OatHeader_124(reader);
					case OatConstants.OAT_VERSION_126:
						return new OatHeader_126(reader);
					case OatConstants.OAT_VERSION_131:
						return new OatHeader_131(reader);
					case OatConstants.OAT_VERSION_138:
						return new OatHeader_138(reader);
					case OatConstants.OAT_VERSION_170:
						return new OatHeader_170(reader);
					case OatConstants.OAT_VERSION_183:
						return new OatHeader_183(reader);
					case OatConstants.OAT_VERSION_195:
						return new OatHeader_195(reader);
					case OatConstants.OAT_VERSION_199:
						return new OatHeader_199(reader);
					case OatConstants.OAT_VERSION_220:
						return new OatHeader_220(reader);
					case OatConstants.OAT_VERSION_223:
						return new OatHeader_223(reader);
					case OatConstants.OAT_VERSION_225:
						return new OatHeader_225(reader);
				}
			}
		}
		throw new UnsupportedOatVersionException(magic, version);
	}

	public final static void parseOatHeader(OatHeader oatHeader, Program oatProgram,
			BinaryReader reader, TaskMonitor monitor, MessageLog log)
			throws UnsupportedOatVersionException, IOException {

		OatBundle bundle = OatBundleFactory.getOatBundle(oatProgram, oatHeader, monitor, log);
		oatHeader.parse(reader, bundle);
		bundle.close();
	}

}
