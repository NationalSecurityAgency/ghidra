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
package ghidra.app.util.bin.format.omf.omf;

import ghidra.app.util.bin.format.omf.OmfUtils;

/**
 * Relocatable OMF record types
 * 
 * @see <a href="http://www.azillionmonkeys.com/qed/Omfg.pdf">OMF: Relocatable Object Module Format</a> 
 */
public class OmfRecordTypes {

	public final static int RHEADR = 0x6E; // Obsolete
	public final static int REGINT = 0x70; // Obsolete
	public final static int REDATA = 0x72; // Obsolete
	public final static int RIDATA = 0x74; // Obsolete
	public final static int OVLDEF = 0x76; // Obsolete 
	public final static int ENDREC = 0x78; // Obsolete 
	public final static int BLKDEF = 0x7A; // Obsolete
	public final static int BLKEND = 0x7C; // Obsolete
	public final static int DEBSYM = 0x7E; // Obsolete
	public final static int THEADR = 0x80;
	public final static int LHEADR = 0x82;
	public final static int PEDATA = 0x84; // Obsolete
	public final static int PIDATA = 0x86; // Obsolete
	public final static int COMENT = 0x88;
	public final static int MODEND = 0x8A;
	public final static int EXTDEF = 0x8C;
	public final static int TYPDEF = 0x8E; // Obsolete 
	public final static int PUBDEF = 0x90;
	public final static int LOCSYM = 0x92; // Obsolete
	public final static int LINNUM = 0x94;
	public final static int LNAMES = 0x96;
	public final static int SEGDEF = 0x98;
	public final static int GRPDEF = 0x9A;
	public final static int FIXUPP = 0x9C;
	public final static int LEDATA = 0xA0;
	public final static int LIDATA = 0xA2;
	public final static int LIBHED = 0xA4; // Obsolete
	public final static int LIBNAM = 0xA6; // Obsolete
	public final static int LIBLOC = 0xA8; // Obsolete
	public final static int LIBDIC = 0xAA; // Obsolete
	public final static int COMDEF = 0xB0;
	public final static int BAKPAT = 0xB2;
	public final static int LEXTDEF = 0xB4;
	public final static int LPUBDEF = 0xB6;
	public final static int LCOMDEF = 0xB8;
	public final static int CEXTDEF = 0xBC;
	public final static int COMDAT = 0xC2;
	public final static int LINSYM = 0xC4;
	public final static int ALIAS = 0xC6;
	public final static int NBKPAT = 0xC8;
	public final static int LLNAMES = 0xCA;
	public final static int VERNUM = 0xCC;
	public final static int VENDEXT = 0xCE;

	public final static int START = 0xF0;
	public final static int END = 0xF1;

	/**
	 * Gets the name of the given record type
	 * 
	 * @param type The record type
	 * @return The name of the given record type
	 */
	public final static String getName(int type) {
		return OmfUtils.getRecordName(type, OmfRecordTypes.class);
	}
}
