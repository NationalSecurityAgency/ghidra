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
/*
 * Created on Feb 4, 2005
 *
 */
package ghidra.app.plugin.processors.sleigh;

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import java.io.IOException;

import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.Encoder;

/**
 *  All the resolved pieces of data needed to build a Varnode
 */
public class VarnodeData {
	public AddressSpace space;
	public long offset;
	public int size;

	/**
	 * Encode the data to stream as an \<addr> element
	 * @param encoder is the stream encoder
	 * @throws IOException for errors writing to the underlying stream
	 */
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_ADDR);
		encoder.writeSpace(ATTRIB_SPACE, space);
		encoder.writeUnsignedInteger(ATTRIB_OFFSET, offset);
		encoder.writeSignedInteger(ATTRIB_SIZE, size);
		encoder.closeElement(ELEM_ADDR);
	}
}
