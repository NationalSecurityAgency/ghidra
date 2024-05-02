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
package ghidra.app.util.bin.format.dwarf.line;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf.attribs.*;

/**
 * Represents an identifier of a value in a DWARFLine/DWARFFile object.
 * <p>
 * Similar to the {@link DWARFAttribute} enum, both are identifiers of an attribute value 
 * that is serialized by a DWARFForm.
 * <p>
 * Users of this enum should be tolerant of unknown values.
 */
public enum DWARFLineContentType {
	DW_LNCT_path(0x1),
	DW_LNCT_directory_index(0x2),
	DW_LNCT_timestamp(0x3),
	DW_LNCT_size(0x4),
	DW_LNCT_MD5(0x5),
	DW_LNCT_lo_user(0x2000),
	DW_LNCT_hi_user(0x3fff),

	DW_LNCT_UNKNOWN(-1); // fake ghidra value

	DWARFLineContentType(int id) {
		this.id = id;
	}

	private final int id;

	public static DWARFLineContentType of(int id) {
		return lookupMap.getOrDefault(id, DW_LNCT_UNKNOWN);
	}

	private static Map<Integer, DWARFLineContentType> lookupMap = buildLookup();

	private static Map<Integer, DWARFLineContentType> buildLookup() {
		Map<Integer, DWARFLineContentType> result = new HashMap<>();
		for (DWARFLineContentType e : values()) {
			result.put(e.id, e);
		}
		return result;
	}

	/**
	 * Defines a {@link DWARFLineContentType} attribute value.
	 */
	public static class Def extends DWARFAttributeDef<DWARFLineContentType> {

		/**
		 * Reads a {@link DWARFLineContentType.Def} instance from the {@link BinaryReader reader}.
		 * <p>
		 * Returns a null if its a end-of-list marker.
		 * <p>
		 * @param reader {@link BinaryReader} stream
		 * @return {@link DWARFLineContentType.Def}, or null if stream was at a end-of-list marker
		 * (which isn't really a thing for line content defs, but is a thing for attribute defs)
		 * @throws IOException if error reading
		 */
		public static Def read(BinaryReader reader) throws IOException {
			DWARFAttributeDef<DWARFLineContentType> tmp =
				DWARFAttributeDef.read(reader, DWARFLineContentType::of);
			if (tmp == null) {
				return null;
			}

			return new Def(tmp.getAttributeId(), tmp.getRawAttributeId(), tmp.getAttributeForm(),
				tmp.getImplicitValue());
		}

		public Def(DWARFLineContentType attributeId, int rawAttributeId, DWARFForm attributeForm,
				long implicitValue) {
			super(attributeId, rawAttributeId, attributeForm, implicitValue);
		}

		public DWARFLineContentType getId() {
			return super.getAttributeId();
		}

		@Override
		protected String getRawAttributeIdDescription() {
			return "DW_LNCT_???? %d (0x%x)".formatted(attributeId, attributeId);
		}

		@Override
		public Def withForm(DWARFForm newForm) {
			return new Def(attributeId, rawAttributeId, newForm, implicitValue);
		}

	}

}
