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
package ghidra.program.model.data;

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import java.io.IOException;

import ghidra.program.database.DBStringMapAdapter;
import ghidra.program.model.pcode.Encoder;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

public class BitFieldPackingImpl implements BitFieldPacking {

	public static final boolean DEFAULT_USE_MS_CONVENTION = false;
	public static final boolean DEFAULT_TYPE_ALIGNMENT_ENABLED = true;
	public static final int DEFAULT_ZERO_LENGTH_BOUNDARY = 0;

	private boolean useMSConvention = DEFAULT_USE_MS_CONVENTION;
	private boolean typeAlignmentEnabled = DEFAULT_TYPE_ALIGNMENT_ENABLED;
	private int zeroLengthBoundary = DEFAULT_ZERO_LENGTH_BOUNDARY;

	@Override
	public boolean useMSConvention() {
		return useMSConvention;
	}

	@Override
	public boolean isTypeAlignmentEnabled() {
		return useMSConvention || typeAlignmentEnabled; // same as PCC_BITFIELD_TYPE_MATTERS
	}

	@Override
	public int getZeroLengthBoundary() {
		return useMSConvention ? 0 : zeroLengthBoundary;
	}

	/**
	 * Control if the alignment and packing of bit-fields follows MSVC conventions.  
	 * When this is enabled it takes precedence over all other bitfield packing controls.
	 * @param useMSConvention true if MSVC packing conventions are used, else false (e.g., GNU conventions apply).
	 */
	public void setUseMSConvention(boolean useMSConvention) {
		this.useMSConvention = useMSConvention;
	}

	/**
	 * Control whether the alignment of bit-field types is respected when laying out structures.
	 * Corresponds to PCC_BITFIELD_TYPE_MATTERS in gcc.
	 * @param typeAlignmentEnabled true if the alignment of the bit-field type should be used
	 * to impact the alignment of the containing structure, and ensure that individual bit-fields 
	 * will not straddle an alignment boundary. 
	 */
	public void setTypeAlignmentEnabled(boolean typeAlignmentEnabled) {
		this.typeAlignmentEnabled = typeAlignmentEnabled;
	}

	/**
	 * Indicate a fixed alignment size in bytes which should be used for zero-length bit-fields.
	 * @param zeroLengthBoundary fixed alignment size as number of bytes for a bit-field 
	 * which follows a zero-length bit-field.  A value of 0 causes zero-length type size to be used.
	 */
	public void setZeroLengthBoundary(int zeroLengthBoundary) {
		this.zeroLengthBoundary = zeroLengthBoundary;
	}

	/**
	 * Save the specified bitfield packing options to the specified DB data map.
	 * @param bitfieldPacking bitfield packing options
	 * @param dataMap DB data map
	 * @param keyPrefix key prefix for all map entries
	 * @throws IOException if an IO error occurs
	 */
	static void save(BitFieldPacking bitfieldPacking, DBStringMapAdapter dataMap,
			String keyPrefix) throws IOException {

		boolean useMSConvention = bitfieldPacking.useMSConvention();
		if (useMSConvention != DEFAULT_USE_MS_CONVENTION) {
			dataMap.put(keyPrefix + "use_MS_convention", Boolean.toString(useMSConvention));
		}

		boolean typeAlignmentEnabled = bitfieldPacking.isTypeAlignmentEnabled();
		if (typeAlignmentEnabled != DEFAULT_TYPE_ALIGNMENT_ENABLED) {
			dataMap.put(keyPrefix + "type_alignment_enabled",
				Boolean.toString(typeAlignmentEnabled));
		}

		int zeroLengthBoundary = bitfieldPacking.getZeroLengthBoundary();
		if (zeroLengthBoundary != DEFAULT_ZERO_LENGTH_BOUNDARY) {
			dataMap.put(keyPrefix + "zero_length_boundary", Integer.toString(zeroLengthBoundary));
		}
	}

	/**
	 * Restore a data organization from the specified DB data map.
	 * @param dataMap DB data map
	 * @param keyPrefix key prefix for all map entries
	 * @return data organization
	 * @throws IOException if an IO error occurs
	 */
	static BitFieldPackingImpl restore(DBStringMapAdapter dataMap, String keyPrefix)
			throws IOException {

		BitFieldPackingImpl bitFieldPacking = new BitFieldPackingImpl();

		bitFieldPacking.useMSConvention =
			dataMap.getBoolean(keyPrefix + ELEM_USE_MS_CONVENTION.name(),
				bitFieldPacking.useMSConvention);

		bitFieldPacking.typeAlignmentEnabled = dataMap.getBoolean(
			keyPrefix + ELEM_TYPE_ALIGNMENT_ENABLED.name(), bitFieldPacking.typeAlignmentEnabled);

		bitFieldPacking.zeroLengthBoundary =
			dataMap.getInt(keyPrefix + ELEM_ZERO_LENGTH_BOUNDARY.name(),
				bitFieldPacking.zeroLengthBoundary);

		return bitFieldPacking;
	}

	/**
	 * Output the details of this bitfield packing to a encoded document formatter.
	 * @param encoder the output document encoder.
	 * @throws IOException if an IO error occurs while encoding/writing output
	 */
	public void encode(Encoder encoder) throws IOException {
		if (useMSConvention == DEFAULT_USE_MS_CONVENTION &&
			typeAlignmentEnabled == DEFAULT_TYPE_ALIGNMENT_ENABLED &&
			zeroLengthBoundary == DEFAULT_ZERO_LENGTH_BOUNDARY) {
			return;		// All defaults
		}
		encoder.openElement(ELEM_BITFIELD_PACKING);
		if (useMSConvention != DEFAULT_USE_MS_CONVENTION) {
			encoder.openElement(ELEM_USE_MS_CONVENTION);
			encoder.writeBool(ATTRIB_VALUE, true);
			encoder.closeElement(ELEM_USE_MS_CONVENTION);
		}
		if (typeAlignmentEnabled != DEFAULT_TYPE_ALIGNMENT_ENABLED) {
			encoder.openElement(ELEM_TYPE_ALIGNMENT_ENABLED);
			encoder.writeBool(ATTRIB_VALUE, false);
			encoder.closeElement(ELEM_TYPE_ALIGNMENT_ENABLED);
		}
		if (zeroLengthBoundary != DEFAULT_ZERO_LENGTH_BOUNDARY) {
			encoder.openElement(ELEM_ZERO_LENGTH_BOUNDARY);
			encoder.writeSignedInteger(ATTRIB_VALUE, zeroLengthBoundary);
			encoder.closeElement(ELEM_ZERO_LENGTH_BOUNDARY);
		}
		encoder.closeElement(ELEM_BITFIELD_PACKING);
	}

	/**
	 * Restore settings from a \<bitfield_packing> tag in an XML stream.
	 * The XML is designed to override existing settings from the default constructor
	 * @param parser is the XML stream
	 */
	protected void restoreXml(XmlPullParser parser) {
		parser.start();
		while (parser.peek().isStart()) {
			XmlElement subel = parser.start();
			String name = subel.getName();
			String value = subel.getAttribute("value");

			if (name.equals(ELEM_USE_MS_CONVENTION.name())) {
				useMSConvention = SpecXmlUtils.decodeBoolean(value);
			}
			else if (name.equals(ELEM_TYPE_ALIGNMENT_ENABLED.name())) {
				typeAlignmentEnabled = SpecXmlUtils.decodeBoolean(value);
			}
			else if (name.equals(ELEM_ZERO_LENGTH_BOUNDARY.name())) {
				zeroLengthBoundary = SpecXmlUtils.decodeInt(value);
			}

			parser.end(subel);
		}
		parser.end();
	}
}
