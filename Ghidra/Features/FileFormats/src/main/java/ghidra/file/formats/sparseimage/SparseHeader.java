/* ###
 * IP: Apache License 2.0
 * NOTE: Based on the simg2img code from The Android Open Source Project
 */
package ghidra.file.formats.sparseimage;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class SparseHeader implements StructConverter {

	private int		magic;			// 0xED26FF3A
	private short	major_version;	
	private short	minor_version;	
	private short	file_hdr_sz;	
	private short	chunk_hdr_sz;	
	private int		blk_sz;			
	private int		total_blks;		
	private int		total_chunks;	
	private int		image_checksum; 
	
	
	public SparseHeader(ByteProvider provider) throws IOException {
		this( new BinaryReader(provider, true) );
	}
	
	public SparseHeader(BinaryReader reader) throws IOException {
		magic = reader.readNextInt();			
		major_version = reader.readNextShort();	
		minor_version = reader.readNextShort();	
		file_hdr_sz = reader.readNextShort();	
		chunk_hdr_sz = reader.readNextShort();	
		blk_sz = reader.readNextInt();			
		total_blks = reader.readNextInt();		
		total_chunks = reader.readNextInt();	
		image_checksum = reader.readNextInt();
	}
	
	public int getMagic() {
		return magic;
	}

	public short getMajor_version() {
		return major_version;
	}

	public short getMinor_version() {
		return minor_version;
	}

	public short getFile_hdr_sz() {
		return file_hdr_sz;
	}

	public short getChunk_hdr_sz() {
		return chunk_hdr_sz;
	}

	public int getBlk_sz() {
		return blk_sz;
	}

	public int getTotal_blks() {
		return total_blks;
	}

	public int getTotal_chunks() {
		return total_chunks;
	}

	public int getImage_checksum() {
		return image_checksum;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("sparse_header", 0);
		structure.add(DWORD, "magic", null);			
		structure.add(WORD, "major_version", null);	
		structure.add(WORD, "minor_version", null);	
		structure.add(WORD, "file_hdr_sz", null);	
		structure.add(WORD, "chunk_hdr_sz", null);	
		structure.add(DWORD, "blk_sz", null);			
		structure.add(DWORD, "total_blks", null);		
		structure.add(DWORD, "total_chunks", null);	
		structure.add(DWORD, "image_checksum", null);
		return structure;
	}

}
