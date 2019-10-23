package ghidra.app.util.bin.format.elf;

import java.util.Formatter;

import ghidra.docking.settings.Settings;
import ghidra.program.model.data.BuiltIn;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Dynamic;
import ghidra.program.model.mem.MemBuffer;

public class AndroidPackedRelocationTableDataType extends BuiltIn implements Dynamic {

	private ElfRelocation[] relocs;
	private int size;

	public AndroidPackedRelocationTableDataType() {
		this(new ElfRelocation[0], -1);
	}

	public AndroidPackedRelocationTableDataType(ElfRelocation[] relocs, int length) {
		this(relocs, length, null);
	}
	
	public AndroidPackedRelocationTableDataType(ElfRelocation[] relocs, int length, DataTypeManager dtm) {
		super(null, "AndroidPackedRelocationTable", dtm);
		this.relocs = relocs;
		this.size = length;		
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new AndroidPackedRelocationTableDataType(relocs, size, dtm);
	}

	@Override
	public String getDescription() {
		return "Android Packed Relocation Table";
	}

	@Override
	public String getDefaultLabelPrefix() {
		return "AndroidPackedRelocationTable";
	}	

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		//TODO I think we need to reparse the data here, as the relocs data is not populated 
		
		if (relocs.length > 0) {
			Formatter formatter = new Formatter();
			
			for(ElfRelocation reloc : relocs) {
				formatter.format("%d,%d,%d \n", reloc.getOffset(), reloc.getRelocationInfo(), reloc.getAddend());
			}
					
			return formatter.toString();
		} else {
			return "No relocs present";
		}
	}

	@Override
	public int getLength() {
		return -1;
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return"Value";
	}

	@Override
	public int getLength(MemBuffer buf, int maxLength) {
		return size;
	}

	@Override
	public boolean canSpecifyLength() {
		return false;
	}

	@Override
	public boolean isDynamicallySized() {
		return true;
	}

	@Override
	public DataType getReplacementBaseType() {
		return ByteDataType.dataType;
	}
}
