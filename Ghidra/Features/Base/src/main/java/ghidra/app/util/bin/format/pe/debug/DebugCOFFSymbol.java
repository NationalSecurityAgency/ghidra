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
import ghidra.program.model.data.*;
import ghidra.util.*;
import ghidra.util.exception.*;

import java.io.*;

/**
 * A class to represent the COFF symbol data structure.
 * <br>
 * <pre>
 * typedef struct _IMAGE_SYMBOL {
 *     union {
 *         BYTE    ShortName[8];
 *         struct {
 *             DWORD   Short;     // if 0, use LongName
 *             DWORD   Long;      // offset into string table
 *         } Name;
 *         DWORD   LongName[2];    // PBYTE [2]
 *     } N;
 *     DWORD   Value;
 *     SHORT   SectionNumber;
 *     WORD    Type;
 *     BYTE    StorageClass;
 *     BYTE    NumberOfAuxSymbols;
 * } IMAGE_SYMBOL;
 * </pre>
 */
public class DebugCOFFSymbol implements StructConverter {
	private static final int NAME_LENGTH = 8;

	/**
	 * The size of the <code>IMAGE_SYMBOL</code> structure.
	 */
    public final static int IMAGE_SIZEOF_SYMBOL = 18;

    //
    // Section values.
    //
    //
    public final static short IMAGE_SYM_UNDEFINED =  0; // Symbol is undefined or is common.
    public final static short IMAGE_SYM_ABSOLUTE  = -1; // Symbol is an absolute value.
    public final static short IMAGE_SYM_DEBUG     = -2; // Symbol is a special debug item.

    //
    // Type (fundamental) values.
    //
    public final static short IMAGE_SYM_TYPE_NULL      = 0x0000;  // no type.
    public final static short IMAGE_SYM_TYPE_VOID      = 0x0001;  //
    public final static short IMAGE_SYM_TYPE_CHAR      = 0x0002;  // type character.
    public final static short IMAGE_SYM_TYPE_SHORT     = 0x0003;  // type short integer.
    public final static short IMAGE_SYM_TYPE_INT       = 0x0004;  //
    public final static short IMAGE_SYM_TYPE_LONG      = 0x0005;  //
    public final static short IMAGE_SYM_TYPE_FLOAT     = 0x0006;  //
    public final static short IMAGE_SYM_TYPE_DOUBLE    = 0x0007;  //
    public final static short IMAGE_SYM_TYPE_STRUCT    = 0x0008;  //
    public final static short IMAGE_SYM_TYPE_UNION     = 0x0009;  //
    public final static short IMAGE_SYM_TYPE_ENUM      = 0x000A;  // enumeration.
    public final static short IMAGE_SYM_TYPE_MOE       = 0x000B;  // member of enumeration.
    public final static short IMAGE_SYM_TYPE_BYTE      = 0x000C;  //
    public final static short IMAGE_SYM_TYPE_WORD      = 0x000D;  //
    public final static short IMAGE_SYM_TYPE_UINT      = 0x000E;  //
    public final static short IMAGE_SYM_TYPE_DWORD     = 0x000F;  //
    public final static short IMAGE_SYM_TYPE_PCODE     = (short)0x8000;

    //
    // Type (derived) values.
    //
    public final static short IMAGE_SYM_DTYPE_NULL       = 0;  // no derived type.
    public final static short IMAGE_SYM_DTYPE_POINTER    = 1;  // pointer.
    public final static short IMAGE_SYM_DTYPE_FUNCTION   = 2;  // function.
    public final static short IMAGE_SYM_DTYPE_ARRAY      = 3;  // array.

    //
    // Storage classes.
    //
    public final static byte IMAGE_SYM_CLASS_END_OF_FUNCTION     = (byte)0xff;
    public final static byte IMAGE_SYM_CLASS_NULL                = 0x00;
    public final static byte IMAGE_SYM_CLASS_AUTOMATIC           = 0x01;
    public final static byte IMAGE_SYM_CLASS_EXTERNAL            = 0x02;
    public final static byte IMAGE_SYM_CLASS_STATIC              = 0x03;
    public final static byte IMAGE_SYM_CLASS_REGISTER            = 0x04;
    public final static byte IMAGE_SYM_CLASS_EXTERNAL_DEF        = 0x05;
    public final static byte IMAGE_SYM_CLASS_LABEL               = 0x06;
    public final static byte IMAGE_SYM_CLASS_UNDEFINED_LABEL     = 0x07;
    public final static byte IMAGE_SYM_CLASS_MEMBER_OF_STRUCT    = 0x08;
    public final static byte IMAGE_SYM_CLASS_ARGUMENT            = 0x09;
    public final static byte IMAGE_SYM_CLASS_STRUCT_TAG          = 0x0A;
    public final static byte IMAGE_SYM_CLASS_MEMBER_OF_UNION     = 0x0B;
    public final static byte IMAGE_SYM_CLASS_UNION_TAG           = 0x0C;
    public final static byte IMAGE_SYM_CLASS_TYPE_DEFINITION     = 0x0D;
    public final static byte IMAGE_SYM_CLASS_UNDEFINED_STATIC    = 0x0E;
    public final static byte IMAGE_SYM_CLASS_ENUM_TAG            = 0x0F;
    public final static byte IMAGE_SYM_CLASS_MEMBER_OF_ENUM      = 0x10;
    public final static byte IMAGE_SYM_CLASS_REGISTER_PARAM      = 0x11;
    public final static byte IMAGE_SYM_CLASS_BIT_FIELD           = 0x12;
    public final static byte IMAGE_SYM_CLASS_FAR_EXTERNAL        = 0x44;
    public final static byte IMAGE_SYM_CLASS_BLOCK               = 0x64;
    public final static byte IMAGE_SYM_CLASS_FUNCTION            = 0x65;
    public final static byte IMAGE_SYM_CLASS_END_OF_STRUCT       = 0x66;
    public final static byte IMAGE_SYM_CLASS_FILE                = 0x67;
    public final static byte IMAGE_SYM_CLASS_SECTION             = 0x68;
    public final static byte IMAGE_SYM_CLASS_WEAK_EXTERNAL       = 0x69;
  //public final static byte IMAGE_SYM_CLASS_CLR_TOKEN           = ??

    private String name;
    private int value;
    private short sectionNumber;
    private short type;
    private byte storageClass;
    private byte numberOfAuxSymbols;
    private DebugCOFFSymbolAux [] auxSymbols;

    public static DebugCOFFSymbol createDebugCOFFSymbol(
            FactoryBundledWithBinaryReader reader, int index,
            DebugCOFFSymbolTable symbolTable) throws IOException {
        return createDebugCOFFSymbol(reader, index, symbolTable.getStringTableIndex());
    }

    public static DebugCOFFSymbol createDebugCOFFSymbol(
            FactoryBundledWithBinaryReader reader, int index,
            int stringTableIndex) throws IOException {
        DebugCOFFSymbol debugCOFFSymbol = (DebugCOFFSymbol) reader.getFactory().create(DebugCOFFSymbol.class);
        debugCOFFSymbol.initDebugCOFFSymbol(reader, index, stringTableIndex);
        return debugCOFFSymbol;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public DebugCOFFSymbol() {}

    private void initDebugCOFFSymbol(FactoryBundledWithBinaryReader reader, int index, int stringTableIndex) throws IOException {
        // read the union first...
        //
        int shortVal = reader.readInt(index);
        if (shortVal != 0) {
            name = reader.readAsciiString(index, NAME_LENGTH);
            index += 8;
        }
        else {
            index += BinaryReader.SIZEOF_INT;
            int longVal = reader.readInt(index);
            index += BinaryReader.SIZEOF_INT;
            if (longVal > 0) {
            	name = reader.readAsciiString(stringTableIndex + longVal);
            } 
        }

        value              = reader.readInt  (index); index += BinaryReader.SIZEOF_INT;
        sectionNumber      = reader.readShort(index); index += BinaryReader.SIZEOF_SHORT;
        type               = reader.readShort(index); index += BinaryReader.SIZEOF_SHORT;
        storageClass       = reader.readByte (index); index += BinaryReader.SIZEOF_BYTE;
        numberOfAuxSymbols = reader.readByte (index); index += BinaryReader.SIZEOF_BYTE;

        // process auxiliary symbols...
        auxSymbols = new DebugCOFFSymbolAux[Conv.byteToInt(numberOfAuxSymbols)];

        for (int i = 0 ; i < numberOfAuxSymbols ; ++i) {

            auxSymbols[i] = DebugCOFFSymbolAux.createDebugCOFFSymbolAux(reader, index, this);
            index += DebugCOFFSymbolAux.IMAGE_SIZEOF_AUX_SYMBOL;
        }
    }

	/**
	 * Returns the auxiliary symbols related to this symbol.
	 * @return the auxiliary symbols related to this symbol
	 */
    public DebugCOFFSymbolAux [] getAuxiliarySymbols() {
        return auxSymbols;
    }
    /**
     * Returns the name of this symbol.
     * @return the name of this symbol
     */
    public String getName() {
        return name;
    }
    /**
     * Returns the value of this symbol.
     * @return the value of this symbol
     */
    public int getValue() {
        return value;
    }
    /**
     * Returns a string equivalent of the value of this symbol.
     * @return a string equivalent of the value of this symbol
     */
    public String getValueAsString() {
        return Integer.toHexString(value);
    }
    /**
     * Returns the section number if this symbol.
     * @return the section number if this symbol
     */
    public int getSectionNumber() {
        return sectionNumber;
    }
	/**
	 * Returns a string equivalent of the section number of this symbol.
	 * @return a string equivalent of the section number of this symbol
	 */
    public String getSectionNumberAsString() {
        switch (sectionNumber) {
            case IMAGE_SYM_UNDEFINED: return "UNDEF";
            case IMAGE_SYM_ABSOLUTE:  return "ABS";
            case IMAGE_SYM_DEBUG:     return "DEBUG";
        }
        return Integer.toHexString(sectionNumber&0xffff);
    }
    /**
     * Returns the type of this symbol.
     * @return the type of this symbol
     */
    public int getType() {
        return type;
    }
	/**
	 * Returns a string equivalent of the type of this symbol.
	 * @return a string equivalent of the type of this symbol
	 */
    public String getTypeAsString() {
        return Integer.toHexString(type&0xffff);
    }
	/**
	 * Returns the storage class of this symbol.
	 * @return the storage class of this symbol
	 */
    public int getStorageClass() {
        return storageClass;
    }
	/**
	 * Returns a string equivalent of the storage class of this symbol.
	 * @return a string equivalent of the storage class of this symbol
	 */
    public String getStorageClassAsString() {
        switch( storageClass ) {
            case IMAGE_SYM_CLASS_END_OF_FUNCTION:  return "END_OF_FUNCTION";
            case IMAGE_SYM_CLASS_NULL:             return "NULL";
            case IMAGE_SYM_CLASS_AUTOMATIC:        return "AUTOMATIC";
            case IMAGE_SYM_CLASS_EXTERNAL:         return "EXTERNAL";
            case IMAGE_SYM_CLASS_STATIC:           return "STATIC";
            case IMAGE_SYM_CLASS_REGISTER:         return "REGISTER";
            case IMAGE_SYM_CLASS_EXTERNAL_DEF:     return "EXTERNAL_DEF";
            case IMAGE_SYM_CLASS_LABEL:            return "LABEL";
            case IMAGE_SYM_CLASS_UNDEFINED_LABEL:  return "UNDEFINED_LABEL";
            case IMAGE_SYM_CLASS_MEMBER_OF_STRUCT: return "MEMBER_OF_STRUCT";
            case IMAGE_SYM_CLASS_ARGUMENT:         return "ARGUMENT";
            case IMAGE_SYM_CLASS_STRUCT_TAG:       return "STRUCT_TAG";
            case IMAGE_SYM_CLASS_MEMBER_OF_UNION:  return "MEMBER_OF_UNION";
            case IMAGE_SYM_CLASS_UNION_TAG:        return "UNION_TAG";
            case IMAGE_SYM_CLASS_TYPE_DEFINITION:  return "TYPE_DEFINITION";
            case IMAGE_SYM_CLASS_UNDEFINED_STATIC: return "UNDEFINED_STATIC";
            case IMAGE_SYM_CLASS_ENUM_TAG:         return "ENUM_TAG";
            case IMAGE_SYM_CLASS_MEMBER_OF_ENUM:   return "MEMBER_OF_ENUM";
            case IMAGE_SYM_CLASS_REGISTER_PARAM:   return "REGISTER_PARAM";
            case IMAGE_SYM_CLASS_BIT_FIELD:        return "BIT_FIELD";
            case IMAGE_SYM_CLASS_FAR_EXTERNAL:     return "FAR_EXTERNAL";
            case IMAGE_SYM_CLASS_BLOCK:            return "BLOCK";
            case IMAGE_SYM_CLASS_FUNCTION:         return "FUNCTION";
            case IMAGE_SYM_CLASS_END_OF_STRUCT:    return "END_OF_STRUCT";
            case IMAGE_SYM_CLASS_FILE:             return "FILE";
            case IMAGE_SYM_CLASS_SECTION:          return "SECTION";
            case IMAGE_SYM_CLASS_WEAK_EXTERNAL:    return "WEAK_EXTERNAL";
          //case IMAGE_SYM_CLASS_CLR_TOKEN:        return "CLR_TOKEN";
        }
        return "STORAGE_CLASS_"+Integer.toHexString(storageClass&0xff);
    }

	/**
	 * Returns the number of auxiliary symbols defined with this symbol.
	 * @return the number of auxiliary symbols defined with this symbol
	 */
    public int getNumberOfAuxSymbols() {
        return numberOfAuxSymbols;
    }

    public DataType toDataType() throws DuplicateNameException, IOException {
    	String structureName = StructConverterUtil.parseName(DebugCOFFSymbol.class);
    	
    	Structure structure = new StructureDataType(structureName + "_" +numberOfAuxSymbols, 0);
    	structure.add(STRING, NAME_LENGTH, "name", null);
    	structure.add(DWORD, "value", null);
    	structure.add(WORD, "sectionNumber", null);
    	structure.add(WORD, "type", null);
    	structure.add(BYTE, "storageClass", null);
    	structure.add(BYTE, "numberOfAuxSymbols", null);

    	for ( DebugCOFFSymbolAux auxSymbol : auxSymbols ) {
			structure.add( auxSymbol.toDataType() );
		}
    	return structure;
    }

}
