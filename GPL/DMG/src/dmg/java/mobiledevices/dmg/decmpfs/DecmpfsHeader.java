/* ###
 * IP: Public Domain
 */
package mobiledevices.dmg.decmpfs;

import java.io.IOException;

import mobiledevices.dmg.ghidra.GBinaryReader;
import mobiledevices.dmg.ghidra.GStringUtilities;

public class DecmpfsHeader /*implements StructConverter*/ {
	private int     compression_magic;
	private int     compression_type;
	private long    uncompressed_size;
	private byte [] attr_bytes;

	public DecmpfsHeader(GBinaryReader reader, int size) throws IOException {
		long index = reader.getPointerIndex();

		this.compression_magic = reader.readNextInt();

		boolean originalEndian = reader.isLittleEndian();
		reader.setLittleEndian( true );

		this.compression_type  = reader.readNextInt();
		this.uncompressed_size = reader.readNextLong();

		reader.setLittleEndian( originalEndian );

		long endIndex = index + size + 1; //TODO always add 1????

		if ( ( endIndex % 2 ) != 0 ) {
			endIndex = endIndex - 1;
		}

		long nElements = endIndex - reader.getPointerIndex();

if ( ( nElements % 2 ) != 0 ) {//TODO
	++nElements;
}
else if ( nElements < 0 ) {//TODO
	System.err.println( "here" );
}
		this.attr_bytes = reader.readNextByteArray( (int)nElements );
	}

	public String getCompressionMagic() {
		return GStringUtilities.toString( compression_magic );
	}

	public int getCompressionType() {
		return compression_type;
	}

	public long getUncompressedSize() {
		return uncompressed_size;
	}

	public byte [] getAttrBytes() {
		return attr_bytes;
	}

//	@Override
//	public DataType toDataType() throws DuplicateNameException, IOException {
//		String name = StructConverterUtil.parseName( DecmpfsHeader.class );
//		Structure struct = new StructureDataType( name + "_" + attr_bytes.length, 0 );
//
//		struct.add( STRING, 4, "compression_magic", null );
//		struct.add( DWORD,     "compression_type",  null );
//		struct.add( QWORD,     "uncompressed_size", null );
//
//		if ( attr_bytes.length > 0 ) {
//			ArrayDataType byteArrayDT = new ArrayDataType( BYTE , attr_bytes.length, BYTE.getLength() );
//			struct.add( byteArrayDT, "attr_bytes", null );
//		}
//		return struct;
//	}
	
}
