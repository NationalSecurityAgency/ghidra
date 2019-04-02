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
package ghidra.pdb.pdbreader.type;

import java.util.ArrayList;
import java.util.List;

import ghidra.pdb.PdbByteReader;
import ghidra.pdb.PdbException;
import ghidra.pdb.pdbreader.*;

/**
 * A class for a specific PDB data type.
 * <P>
 * For more information about PDBs, consult the Microsoft PDB API, see
 * <a href="https://devblogs.microsoft.com/cppblog/whats-inside-a-pdb-file">
 * What's inside a PDB File</a>.
 */
public class ModifierExMsType extends AbstractMsType {

	public static final int PDB_ID = 0x1518;

	// Standard modifiers (reserved 0x0000 - 0x01ff)
	private static final int MOD_INVALID = 0x0000;
	private static final int MOD_CONST = 0x0001;
	private static final int MOD_VOLATILE = 0x0002;
	private static final int MOD_UNALIGNED = 0x0003;

	// HLSL modifiers 0x0200 - 0x03ff
	private static final int MOD_HLSL_UNIFORM = 0x0200;
	private static final int MOD_HLSL_LINE = 0x0201;
	private static final int MOD_HLSL_TRIANGLE = 0x0202;
	private static final int MOD_HLSL_LINEADJ = 0x0203;
	private static final int MOD_HLSL_TRIANGLEADJ = 0x0204;
	private static final int MOD_HLSL_LINEAR = 0x0205;
	private static final int MOD_HLSL_CENTROID = 0x0206;
	private static final int MOD_HLSL_CONSTINTERP = 0x0207;
	private static final int MOD_HLSL_NOPERSPECTIVE = 0x0208;
	private static final int MOD_HLSL_SAMPLE = 0x0209;
	private static final int MOD_HLSL_CENTER = 0x020a;
	private static final int MOD_HLSL_SNORM = 0x020b;
	private static final int MOD_HLSL_UNORM = 0x020c;
	private static final int MOD_HLSL_PRECISE = 0x020d;
	private static final int MOD_HLSL_UAV_GLOBALLY_COHERENT = 0x020e;

	private static final String[] STANDARD_MOD_STRING = new String[4];
	static {
		STANDARD_MOD_STRING[0] = "INVALID ";
		STANDARD_MOD_STRING[1] = "const ";
		STANDARD_MOD_STRING[2] = "volatile ";
		STANDARD_MOD_STRING[3] = "__unaligned ";

	}
	private static final String[] HLSL_MOD_STRING = new String[15];
	static {
		HLSL_MOD_STRING[0] = "__uniform__ ";
		HLSL_MOD_STRING[1] = "__line__ ";
		HLSL_MOD_STRING[2] = "__triangle__ ";
		HLSL_MOD_STRING[3] = "__lineadj__ ";
		HLSL_MOD_STRING[4] = "__triangleadj__ ";
		HLSL_MOD_STRING[5] = "__linear__ ";
		HLSL_MOD_STRING[6] = "__centroid__ ";
		HLSL_MOD_STRING[7] = "__constinterp__ ";
		HLSL_MOD_STRING[8] = "__noperspective__ ";
		HLSL_MOD_STRING[9] = "__sample__ ";
		HLSL_MOD_STRING[10] = "__center__ ";
		HLSL_MOD_STRING[11] = "__snorm__ ";
		HLSL_MOD_STRING[12] = "__unorm__ ";
		HLSL_MOD_STRING[13] = "__precise__ ";
		HLSL_MOD_STRING[14] = "__uav_globally_coherent__ ";
	}

	//==============================================================================================
	private AbstractTypeIndex modifiedTypeIndex;
	//TODO: alternative to List, could create a bunch of booleans (e.g., isConst), and put
	// methods in place to test (e.g., public boolean isConst()).  Then emit() method would
	// have to put the modifier strings in a predesigned order instead of the order that they
	// were found in the record.
	private List<Integer> modifierList = new ArrayList<>();

	//==============================================================================================
	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public ModifierExMsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		modifiedTypeIndex = new TypeIndex32();
		modifiedTypeIndex.parse(reader);
		pdb.pushDependencyStack(
			new CategoryIndex(CategoryIndex.Category.DATA, modifiedTypeIndex.get()));
		pdb.popDependencyStack();
		int count = reader.parseUnsignedShortVal();
		for (int i = 0; i < count; i++) {
			// TODO: Not sure if these are unsigned short or int.
			int modifier = reader.parseUnsignedShortVal();
			if (modifier == MOD_INVALID) {
				// Should not happen, but could output a warning.
			}
			modifierList.add(modifier);
		}
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isConst() {
		for (int val : modifierList) {
			if (val == MOD_CONST) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isVolatile() {
		for (int val : modifierList) {
			if (val == MOD_VOLATILE) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isUnaligned() {
		for (int val : modifierList) {
			if (val == MOD_UNALIGNED) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean IsHlslUniform() {
		for (int val : modifierList) {
			if (val == MOD_HLSL_UNIFORM) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean IsHlslLine() {
		for (int val : modifierList) {
			if (val == MOD_HLSL_LINE) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean IsHlslTriangle() {
		for (int val : modifierList) {
			if (val == MOD_HLSL_TRIANGLE) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean IsHlslLindAdj() {
		for (int val : modifierList) {
			if (val == MOD_HLSL_LINEADJ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean IsHlslTriangleAdj() {
		for (int val : modifierList) {
			if (val == MOD_HLSL_TRIANGLEADJ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean IsHlslLinear() {
		for (int val : modifierList) {
			if (val == MOD_HLSL_LINEAR) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean IsHlslCentroid() {
		for (int val : modifierList) {
			if (val == MOD_HLSL_CENTROID) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean IsHlslConstInterp() {
		for (int val : modifierList) {
			if (val == MOD_HLSL_CONSTINTERP) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean IsHlslNoPerspective() {
		for (int val : modifierList) {
			if (val == MOD_HLSL_NOPERSPECTIVE) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean IsHlslSample() {
		for (int val : modifierList) {
			if (val == MOD_HLSL_SAMPLE) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean IsHlslCenter() {
		for (int val : modifierList) {
			if (val == MOD_HLSL_CENTER) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean IsHlslSNorm() {
		for (int val : modifierList) {
			if (val == MOD_HLSL_SNORM) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean IsHlslUNorm() {
		for (int val : modifierList) {
			if (val == MOD_HLSL_UNORM) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean IsHlslPrecise() {
		for (int val : modifierList) {
			if (val == MOD_HLSL_PRECISE) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean IsHlslUavGloballyCoherent() {
		for (int val : modifierList) {
			if (val == MOD_HLSL_UAV_GLOBALLY_COHERENT) {
				return true;
			}
		}
		return false;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		StringBuilder modBuilder = new StringBuilder();
		for (int modifier : modifierList) {
			modBuilder.append(getModifierString(modifier));
		}
		modBuilder.append(pdb.getTypeRecord(modifiedTypeIndex.get()));
		builder.insert(0, modBuilder);
	}

	private String getModifierString(int modifierVal) {
		if ((modifierVal >= 0x0000) && (modifierVal <= 0x0003)) {
			return STANDARD_MOD_STRING[modifierVal];
		}
		else if ((modifierVal >= 0x0200) && (modifierVal <= 0x020e)) {
			return HLSL_MOD_STRING[modifierVal - 0x0200];
		}
		return STANDARD_MOD_STRING[0];
	}

}
