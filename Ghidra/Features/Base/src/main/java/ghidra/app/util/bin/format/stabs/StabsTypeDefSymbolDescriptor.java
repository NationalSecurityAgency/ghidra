package ghidra.app.util.bin.format.stabs;

import java.util.function.Predicate;
import java.util.regex.Pattern;

import ghidra.app.util.bin.format.stabs.types.StabsTypeDescriptor;
import ghidra.app.util.bin.format.stabs.types.StabsTypeDescriptorFactory;
import ghidra.program.model.data.BuiltIn;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.TypedefDataType;

import static ghidra.program.model.data.DataTypeConflictHandler.REPLACE_HANDLER;

/**
 * TypeDef implementation of the StabSymbolDescriptor and StabTypeDescriptor
 */
public class StabsTypeDefSymbolDescriptor extends AbstractStabsSymbolDescriptor
	implements StabsTypeDescriptor {

		private static final Predicate<String> VOID_PTR_PATTERN =
			Pattern.compile("t((\\d+)|(\\((\\d+),(\\d+)\\)))=\\1").asMatchPredicate();

		private final DataType dt;
		private final StabsTypeNumber typeNumber;
		private final StabsTypeDescriptor type;

		/**
		 * Constructs a new StabsTypeDefSymbolDescriptor
		 * @param stab the portion of the stab containing this descriptor
		 * @param file the file containing this descriptor
		 * @throws StabsParseException if the descriptor or one it relies on is invalid
		 */
		StabsTypeDefSymbolDescriptor(String stab, StabsFile file) throws StabsParseException {
			super(stab, file);
			String subStab = stab.substring(name.length()+1);
			this.typeNumber = new StabsTypeNumber(subStab);
			if (StabsUtils.isBuiltin(name)) {
				this.type = null;
				this.dt = StabsUtils.getBuiltin(name);
			} else if (VOID_PTR_PATTERN.test(subStab)) {
				this.type = null;
				this.dt = dtm.getPointer(DataType.VOID);
			} else {
				String typeStab;
				if (getTypeSubStab().charAt(0) == 't') {
					typeStab = getTypeSubStab().substring(1);
				} else {
					typeStab = getTypeSubStab();
				}
				this.type = StabsTypeDescriptorFactory.getTypeDescriptor(this, typeStab);
				if (type != null) {
					this.dt = getTypeDefType();
				} else {
					this.dt = null;
				}
			}
			file.addType(this, typeNumber);
		}

		private DataType getTypeDefType() {
			switch (type.getType()) {
				case BUILTIN:
					return type.getDataType();
				default:
					if (type.getDataType().getName().equals(name)) {
						if (type.getDataType().getCategoryPath().equals(path)) {
							return type.getDataType();
						}
					}
					DataType tmpDt = dtm.getDataType(path, name);
					if (tmpDt instanceof BuiltIn && tmpDt.getLength() > 0) {
						// handles ulong, uint, etc.
						return tmpDt;
					}
					tmpDt = new TypedefDataType(path, name, type.getDataType());
					return dtm.resolve(tmpDt, REPLACE_HANDLER);
					
			}
		}

		@Override
		public DataType getDataType() {
			return dt;
		}

		@Override
		public StabsSymbolDescriptorType getSymbolDescriptorType() {
			return StabsSymbolDescriptorType.TYPEDEF;
		}

		@Override
		public StabsSymbolDescriptor getSymbolDescriptor() {
			return this;
		}

		@Override
		public StabsTypeDescriptorType getType() {
			return StabsTypeDescriptorType.TYPE_REFERENCE;
		}

		@Override
		public StabsTypeDescriptor getTypeInformation() {
			return this;
		}

		@Override
		public int getLength() {
			return type.getLength()+1;
		}
}
