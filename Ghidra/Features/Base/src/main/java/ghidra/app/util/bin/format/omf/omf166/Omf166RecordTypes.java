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
package ghidra.app.util.bin.format.omf.omf166;

import ghidra.app.util.bin.format.omf.OmfUtils;

/**
 * OMF-166 record types
 * 
 * @see <a href="https://www.keil.com/download/files/omf166.pdf">OMF-166 Description</a> 
 */
public class Omf166RecordTypes {

	public final static int RTXDEF = 0x30;
	public final static int DEPLST = 0x70;
	public final static int REGMSK = 0x72;
	public final static int TYPNEW = 0xF0;
	public final static int BLKEND = 0x7C;
	public final static int THEADR = 0x80;
	public final static int LHEADR = 0x82;
	public final static int COMMENT = 0x88;
	public final static int MODEND = 0x8A;
	public final static int LINNUM = 0x94;
	public final static int LNAMES = 0x96;
	public final static int LIBLOC = 0xA8;
	public final static int LIBNAMES = 0xA6;
	public final static int LIBDICT = 0xAA;
	public final static int LIBHDR = 0xBA;
	public final static int PHEADR = 0xE0;
	public final static int PECDEF = 0xE4;
	public final static int SSKDEF = 0xE5;
	public final static int MODINF = 0xE7;
	public final static int TSKDEF = 0xE1;
	public final static int REGDEF = 0xE3;
	public final static int SEDEF = 0xB0;
	public final static int TYPDEF = 0xB2;
	public final static int GRPDEF = 0xB1;
	public final static int PUBDEF = 0xB3;
	public final static int GLBDEF = 0xE6;
	public final static int EXTDEF = 0x8C;
	public final static int LOCSYM = 0xB5;
	public final static int BLKDEF = 0xB7;
	public final static int DEBSYM = 0xB6;
	public final static int LEDATA = 0xB8;
	public final static int PEDATA = 0xB9;
	public final static int VECTAB = 0xE9;
	public final static int FIXUPP = 0xB4;
	public final static int TSKEND = 0xE2;
	public final static int XSECDEF = 0xC5;

	/**
	 * Gets the name of the given record type
	 * 
	 * @param type The record type
	 * @return The name of the given record type
	 */
	public final static String getName(int type) {
		return OmfUtils.getRecordName(type, Omf166RecordTypes.class);
	}
}
