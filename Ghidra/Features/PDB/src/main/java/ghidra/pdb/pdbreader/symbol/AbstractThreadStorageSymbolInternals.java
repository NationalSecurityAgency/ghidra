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
import ghidra.pdb.pdbreader.*;

/**
 * This class represents various flavors of Internals of Thread Storage symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractThreadStorageSymbolInternals extends AbstractSymbolInternals {

	/**
	 * Implementing class must initialize {@link #typeIndex}, {@link #offset}, and {@link #name}
	 * in the {@link #create()} method.  These, as well as {@link #segment}, must be parsed in
	 * the {@link #parse(PdbByteReader)} method in the appropriate order pertinent to itself.
	 */
	protected AbstractTypeIndex typeIndex;
	protected AbstractOffset offset;
	protected int segment;
	protected AbstractString name;

	/**
	 * Constructor for this symbol internals.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 */
	public AbstractThreadStorageSymbolInternals(AbstractPdb pdb) {
		super(pdb);
		pdb.pushDependencyStack(new CategoryIndex(CategoryIndex.Category.DATA, typeIndex.get()));
		pdb.popDependencyStack();
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
	 * Returns the type index.
	 * @return Type index.
	 */
	public int getTypeIndex() {
		return typeIndex.get();
	}

	/**
	 * Returns the name.
	 * @return Name.
	 */
	public String getName() {
		return name.get();
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(String.format(": [%04X:%08X], Type: %s, %s", segment, offset.get(),
			pdb.getTypeRecord(typeIndex.get()).toString(), name));
	}

}
