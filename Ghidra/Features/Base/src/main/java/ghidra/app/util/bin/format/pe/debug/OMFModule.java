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
package ghidra.app.util.bin.format.pe.debug;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.*;

import java.io.*;

/**
 * <pre>
 * typedef struct OMFModule {
 *     unsigned short  ovlNumber;      // overlay number
 *     unsigned short  iLib;           // library that the module was linked from
 *     unsigned short  cSeg;           // count of number of segments in module
 *     char            Style[2];       // debugging style "CV"
 *     OMFSegDesc      SegInfo[1];     // describes segments in module
 *     char            Name[];         // length prefixed module name padded to long word boundary
 * } OMFModule;
 * </pre>
 */
public class OMFModule {
    private short ovlNumber;
    private short iLib;
    private short cSeg;
    private short style;
    private OMFSegDesc [] segDescArr;
    private String name;

    static OMFModule createOMFModule(
            FactoryBundledWithBinaryReader reader, int ptr, int byteCount)
            throws IOException {
        OMFModule omfModule = (OMFModule) reader.getFactory().create(OMFModule.class);
        omfModule.initOMFModule(reader, ptr, byteCount);
        return omfModule;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public OMFModule() {}

    private void initOMFModule(FactoryBundledWithBinaryReader reader, int ptr, int byteCount) throws IOException {
        int index = ptr;

        this.ovlNumber = reader.readShort(index); index+=BinaryReader.SIZEOF_SHORT;
        this.iLib      = reader.readShort(index); index+=BinaryReader.SIZEOF_SHORT;
        this.cSeg      = reader.readShort(index); index+=BinaryReader.SIZEOF_SHORT;
        this.style     = reader.readShort(index); index+=BinaryReader.SIZEOF_SHORT;

        this.segDescArr = new OMFSegDesc[cSeg];

        for (int i = 0 ; i < cSeg ; ++i) {
            segDescArr[i] = OMFSegDesc.createOMFSegDesc(reader, index);

            index += OMFSegDesc.IMAGE_SIZEOF_OMF_SEG_DESC;
        }

        ++index; // why do we need to increment?????

        name = reader.readAsciiString(index);
    }

    public short getOvlNumber() {
		return ovlNumber;
	}
    public short getILib() {
		return iLib;
	}
    public short getStyle() {
		return style;
	}
    public String getName() {
		return name;
	}

	/**
	 * Returns the OMF segment descriptions in this OMF module.
	 * @return the OMF segment descriptions in this OMF module
	 */
    public OMFSegDesc [] getOMFSegDescs() {
        return segDescArr;
    }
}
