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
package ghidra.app.util.bin.format.coff.archive;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.coff.CoffException;
import ghidra.program.model.data.*;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * A class that represents a COFF archive file (ie. MS .lib files, Unix .ar files)
 * <p>
 * COFF archives are very primitive compared to containers like ZIP or even TAR.
 * <p>
 * The name of entries (ie. files) inside the archive is limited to 16 bytes, and to 
 * support longer names a couple of different schemes have been invented.  See the
 * comments in {@link CoffArchiveMemberHeader#read(BinaryReader, LongNamesMember)} for
 * decoding the name.
 */
public final class CoffArchiveHeader implements StructConverter {

	/**
	 * Returns true if the data contained in the {@link ByteProvider provider} contains
	 * a COFF Archive file.
	 * <p>
	 * @param provider
	 * @return
	 * @throws IOException
	 */
	public static boolean isMatch(ByteProvider provider) throws IOException {
		return (provider.length() > CoffArchiveConstants.MAGIC_LEN) && CoffArchiveConstants.MAGIC
				.equals(new String(provider.readBytes(0, CoffArchiveConstants.MAGIC_LEN)));
	}

	/**
	 * Reads and parses the headers and meta-data in a COFF Archive file.
	 * <p>
	 * Returns a {@link CoffArchiveHeader} that has a list of the 
	 * {@link CoffArchiveMemberHeader members} in the archive.
	 * <p>
	 * @param provider
	 * @param monitor
	 * @return
	 * @throws CoffException
	 * @throws IOException
	 */
	public static CoffArchiveHeader read(ByteProvider provider, TaskMonitor monitor)
			throws CoffException, IOException {
		if (!isMatch(provider)) {
			return null;
		}
		BinaryReader reader = new BinaryReader(provider, false/*does not really matter*/);

		reader.setPointerIndex(CoffArchiveConstants.MAGIC_LEN);
		int memberNum = 0;

		CoffArchiveHeader cah = new CoffArchiveHeader();

		long eofPos = reader.length() - CoffArchiveMemberHeader.CAMH_MIN_SIZE;

		while (reader.getPointerIndex() < eofPos) {
			if (monitor.isCancelled()) {
				break;
			}

			try {
				CoffArchiveMemberHeader camh =
					CoffArchiveMemberHeader.read(reader, cah._longNameMember);

				if (camh.getName().equals(CoffArchiveMemberHeader.SLASH)) {
					switch (memberNum) {
						case 0:
							cah._firstLinkerMember = new FirstLinkerMember(reader, camh, true);
							break;
						case 1:
							cah._secondLinkerMember = new SecondLinkerMember(reader, camh, true);
							break;
						default:
							throw new CoffException(
								"Invalid COFF: multiple 1st and 2nd linker members detected.");
					}
				}
				else if (camh.getName().equals(CoffArchiveMemberHeader.SLASH_SLASH)) {
					if (cah._longNameMember == null) {
						cah._longNameMember = new LongNamesMember(reader, camh);
					}
					else {
						throw new CoffException(
							"Invalid COFF: multiple long name members detected.");
					}
				}
				cah._memberHeaders.add(camh);
				memberNum++;

				reader.setPointerIndex(camh.getPayloadOffset() + camh.getSize());
			}
			catch (IOException e) {
				// if we run into bad data, return partial success if there has been at least some
				// good ones, otherwise propagate the exception upwards
				if (memberNum <= 3) {
					throw e;
				}
				Msg.warn(CoffArchiveMemberHeader.class, "Problem reading COFF archive headers in " +
					provider.getFSRL() + ", only " + memberNum + " members found.", e);
				break;
			}
		}

		// TODO: check for null terminators in the longname string table vs. \n terminators
		cah.isMS = (cah._firstLinkerMember != null && cah._secondLinkerMember != null &&
			cah._longNameMember != null);

		return cah;
	}

	private FirstLinkerMember _firstLinkerMember;
	private SecondLinkerMember _secondLinkerMember;
	private LongNamesMember _longNameMember;
	private List<CoffArchiveMemberHeader> _memberHeaders = new ArrayList<>();
	private boolean isMS = false;

	protected CoffArchiveHeader() {
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(StructConverterUtil.parseName(CoffArchiveHeader.class), 0);
		struct.add(STRING, CoffArchiveConstants.MAGIC_LEN, "magic", null);
		return struct;
	}

	public List<CoffArchiveMemberHeader> getArchiveMemberHeaders() {
		return _memberHeaders;
	}

	public FirstLinkerMember getFirstLinkerMember() {
		return _firstLinkerMember;
	}

	public SecondLinkerMember getSecondLinkerMember() {
		return _secondLinkerMember;
	}

	public LongNamesMember getLongNameMember() {
		return _longNameMember;
	}

	/**
	 * Returns true if this COFF archive seems to be a Microsoft lib file (ie.
	 * has linker members and other features specific to MS)
	 * @return
	 */
	public boolean isMSFormat() {
		return isMS;
	}
}
