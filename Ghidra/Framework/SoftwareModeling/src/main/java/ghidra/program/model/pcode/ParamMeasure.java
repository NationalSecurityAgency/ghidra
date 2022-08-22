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
package ghidra.program.model.pcode;

import ghidra.program.model.data.DataType;

/**
 * ParamMeasure
 * 
 * 
 *
 */

public class ParamMeasure {
	private Varnode vn;
	private DataType dt;
	private Integer rank;

	/**
	 * Constructs a ParamMeasure Object.
	 * <b>The ParamMeasure will be empty until {@link #readXml} is invoked.</b>
	 */
	public ParamMeasure() {
		vn = null;
		dt = null;
		rank = null;
	}

	public boolean isEmpty() {
		if (vn == null) {
			return true;
		}
		return false;
	}

	/**
	 * Decode a ParamMeasure object from the stream.
	 * @param decoder is the stream decoder
	 * @param factory pcode factory
	 * @throws DecoderException for an invalid encoding
	 */
	public void decode(Decoder decoder, PcodeFactory factory) throws DecoderException {
		vn = Varnode.decode(decoder, factory);
		dt = factory.getDataTypeManager().decodeDataType(decoder);
		int rankel = decoder.openElement(ElementId.ELEM_RANK);
		rank = (int) decoder.readSignedInteger(AttributeId.ATTRIB_VAL);
		decoder.closeElement(rankel);
	}

	public Varnode getVarnode() {
		return vn;
	}

	public DataType getDataType() {
		return dt;
	}

	public Integer getRank() {
		return rank;
	}
}
