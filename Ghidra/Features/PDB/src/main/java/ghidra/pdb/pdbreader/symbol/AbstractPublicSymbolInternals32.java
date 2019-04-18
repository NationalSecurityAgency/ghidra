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
package ghidra.pdb.pdbreader.symbol;

import ghidra.pdb.PdbByteReader;
import ghidra.pdb.PdbException;
import ghidra.pdb.pdbreader.*;

/**
 * This class represents various flavors of Internals of newer Public symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractPublicSymbolInternals32 extends AbstractSymbolInternals {

	/**
	 * Implementing class must initialize {@link #offset} and {@link #name} in the
	 * {@link #create()} method.
	 */
	protected AbstractOffset offset;
	protected int segment;
	protected AbstractString name;
	protected long flags;
	protected boolean isCode;
	protected boolean isFunction;
	protected boolean isManaged;
	protected boolean isMicrosoftIntermediateLanguage;

	/**
	 * Constructor for this symbol internals.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 */
	public AbstractPublicSymbolInternals32(AbstractPdb pdb) {
		super(pdb);
	}

	/**
	 * Returns the offset.
	 * @return Offset.
	 */
	public long getOffset() {
		return offset.get();
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
		return name.get();
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
			String.format(": [%04X:%08X], Flags: %08x, %s", segment, offset.get(), flags, name));
	}

	@Override
	public void parse(PdbByteReader reader) throws PdbException {
		flags = reader.parseUnsignedIntVal();
		offset.parse(reader);
		segment = reader.parseUnsignedShortVal();
		name.parse(reader);
		processFlags(flags);
	}

	private void processFlags(long flagsIn) {
		isCode = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		isFunction = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		isManaged = ((flagsIn & 0x0001) == 0x0001);
		flagsIn >>= 1;
		isMicrosoftIntermediateLanguage = ((flagsIn & 0x0001) == 0x0001);
		//TODO: Maybe study more.  Remaining bits are supposed to be zero, but there is also
		// a grfFlags that these are unioned with.
	}

}
