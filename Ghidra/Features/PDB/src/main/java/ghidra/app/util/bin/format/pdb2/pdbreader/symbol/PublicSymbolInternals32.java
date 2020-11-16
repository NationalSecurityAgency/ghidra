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
package ghidra.app.util.bin.format.pdb2.pdbreader.symbol;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * This class represents various flavors of Internals of newer Public symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class PublicSymbolInternals32 extends AbstractSymbolInternals {

	/**
	 * Factory for "32" version of PublicSymbolInternals32.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this internals is deserialized.
	 * @return the parsed instance.
	 * @throws PdbException upon error parsing a field.
	 */
	public static PublicSymbolInternals32 parse32(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		PublicSymbolInternals32 result = new PublicSymbolInternals32(pdb);
		long flags = reader.parseUnsignedIntVal();
		result.offset = reader.parseVarSizedOffset(32);
		result.segment = pdb.parseSegment(reader);
		result.name = reader.parseString(pdb, StringParseType.StringUtf8Nt);
		processFlags(result, flags);
		return result;
	}

	/**
	 * Factory for "32St" version of PublicSymbolInternals32.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this internals is deserialized.
	 * @return the parsed instance.
	 * @throws PdbException upon error parsing a field.
	 */
	public static PublicSymbolInternals32 parse32St(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		PublicSymbolInternals32 result = new PublicSymbolInternals32(pdb);
		long flags = reader.parseUnsignedIntVal();
		result.offset = reader.parseVarSizedOffset(32);
		result.segment = pdb.parseSegment(reader);
		result.name = reader.parseString(pdb, StringParseType.StringUtf8St);
		processFlags(result, flags);
		return result;
	}

	protected long offset;
	protected int segment;
	protected String name;
	protected long flags;
	protected boolean isCode;
	protected boolean isFunction;
	protected boolean isManaged;
	protected boolean isMicrosoftIntermediateLanguage;

	/**
	 * Constructor for this symbol internals.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 */
	public PublicSymbolInternals32(AbstractPdb pdb) {
		super(pdb);
	}

	/**
	 * Returns the offset.
	 * @return Offset.
	 */
	public long getOffset() {
		return offset;
	}

	/**
	 * Returns the segment.
	 * @return Segment.
	 */
	public int getSegment() {
		return segment;
	}

	/**
	 * Returns the name.
	 * @return Name.
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns the flags.
	 * @return Flags.
	 */
	public long getFlags() {
		return flags;
	}

	/**
	 * Tells whether it is code.
	 * @return True if it is code.
	 */
	public boolean isCode() {
		return isCode;
	}

	/**
	 * Tells whether the it is a function.
	 * @return True if it is a function.
	 */
	public boolean isFunction() {
		return isFunction;
	}

	/**
	 * Tells whether the the code is managed.
	 * @return True if the code is managed.
	 */
	public boolean isManaged() {
		return isManaged;
	}

	/**
	 * Tells whether it is Microsoft Intermediate Language.
	 * @return True if it is Microsoft Intermediate Language.
	 */
	public boolean isMicrosoftIntermediateLanguage() {
		return isMicrosoftIntermediateLanguage;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(
			String.format(": [%04X:%08X], Flags: %08x, %s", segment, offset, flags, name));
	}

	private static void processFlags(PublicSymbolInternals32 internals, long flagsIn) {
		internals.flags = flagsIn;
		internals.isCode = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		internals.isFunction = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		internals.isManaged = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		internals.isMicrosoftIntermediateLanguage = ((flagsIn & 0x0001) == 0x0001);
		//TODO: Maybe study more.  Remaining bits are supposed to be zero, but there is also
		// a grfFlags that these are unioned with.
	}

}
