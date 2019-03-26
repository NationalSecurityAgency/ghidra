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
package ghidra.app.util.bin.format.pe.cli.tables.flags;

import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.EnumDataType;

public class CliFlags {
	public static final String PATH = "/PE/CLI/Flags";
	
	public static class CliEnumAssemblyFlags extends EnumDataType {
		private static final long serialVersionUID = 1L;
		
		/** A statically defined instance.*/
	    public final static CliEnumAssemblyFlags dataType = new CliEnumAssemblyFlags();
		
		public CliEnumAssemblyFlags() {
			super(new CategoryPath(PATH), "AssemblyFlags", 4);
			// TODO: specify CategoryPath, etc.
			String prefix = "";
			add(prefix+"PublicKey", 0x00000001);
			add(prefix+"Retargetable", 0x00000100);
			add(prefix+"DisableJITcompileOptimizer", 0x00004000);
			add(prefix+"EnableJITcompileTracking", 0x00008000);
		}
	}
	
	public static class CliEnumAssemblyHashAlgorithm extends EnumDataType {
		private static final long serialVersionUID = 1L;
		
		/** A statically defined instance.*/
	    public final static CliEnumAssemblyHashAlgorithm dataType = new CliEnumAssemblyHashAlgorithm();
		
		public CliEnumAssemblyHashAlgorithm() {
			super(new CategoryPath(PATH), "AssemblyHash", 4);
			// TODO: specify CategoryPath, etc.
			String prefix = "";
			add(prefix+"None", 0x00000000);
			add(prefix+"Reserved (MD5)", 0x00008003);
			add(prefix+"SHA1", 0x00008004);
		}
	}
	
	public static class CliEnumEventAttributes extends EnumDataType {
		private static final long serialVersionUID = 1L;
		
		/** A statically defined instance.*/
	    public final static CliEnumEventAttributes dataType = new CliEnumEventAttributes();
		
		public CliEnumEventAttributes() {
			super(new CategoryPath(PATH), "EventAttributes", 2);
			// TODO: specify CategoryPath, etc.
			String prefix = "";
			add(prefix+"SpecialName", 0x0200);
			add(prefix+"RTSpecialName", 0x0400);
		}
	}
	
	public static class CliEnumFieldAttributes extends EnumDataType {
		private static final long serialVersionUID = 1L;
		
		/** A statically defined instance.*/
	    public final static CliEnumFieldAttributes dataType = new CliEnumFieldAttributes();
		
		public CliEnumFieldAttributes() {
			super(new CategoryPath(PATH), "FieldAttributes", 2);
			// TODO: specify CategoryPath, etc.
			String prefix = "";
			add(prefix+"Access_CompilerControlled", 0x0000);
			add(prefix+"Access_Private", 0x0001);
			add(prefix+"Access_FamANDAssem", 0x0002);
			add(prefix+"Access_Assembly", 0x0003);
			add(prefix+"Access_Family", 0x0004);
			add(prefix+"Access_FamORAssem", 0x0005);
			add(prefix+"Access_Public", 0x0006);
			add(prefix+"Static", 0x0010);
			add(prefix+"InitOnly", 0x0020);
			add(prefix+"Literal", 0x0040);
			add(prefix+"NotSerialized", 0x0080);
			add(prefix+"SpecialName", 0x0200);
			add(prefix+"PInvokeImpl", 0x2000);
			add(prefix+"RTSpecialName", 0x0400);
			add(prefix+"HasFieldMarshal", 0x1000);
			add(prefix+"HasDefault", 0x8000);
			add(prefix+"HasFieldRVA", 0x0100);
		}
	}
	
	public static class CliEnumFileAttributes extends EnumDataType {
		private static final long serialVersionUID = 1L;
		
		/** A statically defined instance.*/
	    public final static CliEnumFileAttributes dataType = new CliEnumFileAttributes();
		
		public CliEnumFileAttributes() {
			super(new CategoryPath(PATH), "FileAttributes", 4);
			// TODO: specify CategoryPath, etc.
			String prefix = "";
			add(prefix+"ContainsMetaData", 0x0000);
			add(prefix+"ContainsNoMetaData", 0x0001);
		}
	}
	
	public static class CliEnumGenericParamAttributes extends EnumDataType {
		private static final long serialVersionUID = 1L;
		
		/** A statically defined instance.*/
	    public final static CliEnumGenericParamAttributes dataType = new CliEnumGenericParamAttributes();
		
		public CliEnumGenericParamAttributes() {
			super(new CategoryPath(PATH), "GenericParamAttributes", 2);
			// TODO: specify CategoryPath, etc.
			String prefix = "";
			add(prefix+"Variance_None", 0x0000);
			add(prefix+"Covariant", 0x0001);
			add(prefix+"Contravariant", 0x0002);
			add(prefix+"ReferenceTypeConstraint", 0x0004);
			add(prefix+"NotNullableValueTypeConstraint", 0x0008);
			add(prefix+"DefaultConstructorContstraint", 0x0010);
		}
	}
	
	public static class CliEnumPInvokeAttributes extends EnumDataType {
		private static final long serialVersionUID = 1L;
		
		/** A statically defined instance.*/
	    public final static CliEnumPInvokeAttributes dataType = new CliEnumPInvokeAttributes();
		
		public CliEnumPInvokeAttributes() {
			super(new CategoryPath(PATH), "PInvokeAttributes", 2);
			// TODO: specify CategoryPath, etc.
			String prefix = "";
			add(prefix+"NoMangle", 0x0001);

			add(prefix+"CharSetNotSpec", 0x0000);
			add(prefix+"CharSetAnsi", 0x0002);
			add(prefix+"CharSetUnicode", 0x0004);
			add(prefix+"CharSetAuto", 0x0006);
			
			add(prefix+"SupportsLastError", 0x0040);
			
			add(prefix+"CallConvPlatformapi", 0x0100);
			add(prefix+"CallConvCdecl", 0x0200);
			add(prefix+"CallConvStdcall", 0x0300);
			add(prefix+"CallConvThiscall", 0x0400);
			add(prefix+"CallConvFastcall", 0x0500);
		}
	}
	
	public static class CliEnumManifestResourceAttributes extends EnumDataType {
		private static final long serialVersionUID = 1L;
		
		/** A statically defined instance.*/
	    public final static CliEnumManifestResourceAttributes dataType = new CliEnumManifestResourceAttributes();
		
		public CliEnumManifestResourceAttributes() {
			super(new CategoryPath(PATH), "ManifestResourceAttributes", 4);
			// TODO: specify CategoryPath, etc.
			String prefix = "";
			add(prefix+"Public", 0x0001);
			add(prefix+"Private", 0x0002);
		}
	}

	public static class CliEnumMethodAttributes extends EnumDataType {
		private static final long serialVersionUID = 1L;
		
		/** A statically defined instance.*/
	    public final static CliEnumMethodAttributes dataType = new CliEnumMethodAttributes();
		
		public CliEnumMethodAttributes() {
			super(new CategoryPath(PATH), "MethodAttributes", 2);
			// TODO: specify CategoryPath, etc.
			String prefix = "MAccess_";
			add(prefix+"CompilerControlled", 0x0000);
			add(prefix+"Private", 0x0001);
			add(prefix+"FamANDAssem", 0x0002);
			add(prefix+"Assem", 0x0003);
			add(prefix+"Family", 0x0004);
			add(prefix+"FamORAssem", 0x0005);
			add(prefix+"Public", 0x0006);
			
			prefix = "";
			add(prefix+"Static", 0x0010);
			add(prefix+"Final", 0x0020);
			add(prefix+"Virtual", 0x0040);
			add(prefix+"HideBySig", 0x0080);
			
			prefix = "VtableLayout_";
//			add(prefix+"ReuseSlot", 0x0000); // TODO: this will not work (it will conflict with CompilerControlled)
			add(prefix+"NewSlot", 0x0100);

			prefix = "";
			add(prefix+"Strict", 0x0200);
			add(prefix+"Abstract", 0x0400);
			add(prefix+"SpecialName", 0x0800);
			
			add(prefix+"PInvokeImpl", 0x2000);
			add(prefix+"UnmanagedExport", 0x0008);

			add(prefix+"RTSpecialName", 0x1000);
			add(prefix+"HasSecurity", 0x4000);
			add(prefix+"RequireSecObject", 0x8000);
		}
	}

	public static class CliEnumMethodImplAttributes extends EnumDataType {
		private static final long serialVersionUID = 1L;
		
		/** A statically defined instance.*/
	    public final static CliEnumMethodImplAttributes dataType = new CliEnumMethodImplAttributes();
		
		public CliEnumMethodImplAttributes() {
			super(new CategoryPath(PATH), "MethodImplAttributes", 2);
			// TODO: specify CategoryPath, etc.
			String prefix = "CodeType_";
			add(prefix+"IL", 0x0000);
			add(prefix+"Native", 0x0001);
			add(prefix+"OPTIL", 0x0002);
			add(prefix+"Runtime", 0x0003);
			
			prefix = "";
			add(prefix+"Unmanaged", 0x0004);
//			add(prefix+"Managed", 0x0000); // TODO: This will not work (Will conflict with IL)
			
			add(prefix+"ForwardRef", 0x0010);
			add(prefix+"PreserveSig", 0x0080);
			add(prefix+"InternalCall", 0x1000);
			add(prefix+"Synchronized", 0x0020);
			add(prefix+"NoInlining", 0x0008);
			add(prefix+"MaxMethodImplVal", 0xffff);
			add(prefix+"NoOptimization", 0x0040);
		}
	}

	public static class CliEnumMethodSemanticsAttributes extends EnumDataType {
		private static final long serialVersionUID = 1L;
		
		/** A statically defined instance.*/
	    public final static CliEnumMethodSemanticsAttributes dataType = new CliEnumMethodSemanticsAttributes();
		
		public CliEnumMethodSemanticsAttributes() {
			super(new CategoryPath(PATH), "MethodSemanticsAttributes", 2);
			// TODO: specify CategoryPath, etc.
			String prefix = "";
			add(prefix+"Setter", 0x0001);
			add(prefix+"Getter", 0x0002);
			add(prefix+"Other", 0x0004);
			add(prefix+"AddOn", 0x0008);
			add(prefix+"RemoveOn", 0x0010);
			add(prefix+"Fire", 0x0020);
		}
	}

	public static class CliEnumParamAttributes extends EnumDataType {
		private static final long serialVersionUID = 1L;
		
		/** A statically defined instance.*/
	    public final static CliEnumParamAttributes dataType = new CliEnumParamAttributes();
		
		public CliEnumParamAttributes() {
			super(new CategoryPath(PATH), "ParamAttributes", 2);
			// TODO: specify CategoryPath, etc.
			String prefix = "";
			add(prefix+"In", 0x0001);
			add(prefix+"Out", 0x0002);
			add(prefix+"Optional", 0x0010);
			add(prefix+"HasDefault", 0x1000);
			add(prefix+"HasFieldMarshal", 0x2000);
			add(prefix+"Unused", 0xcfe0);
		}
	}

	public static class CliEnumPropertyAttributes extends EnumDataType {
		private static final long serialVersionUID = 1L;
		
		/** A statically defined instance.*/
	    public final static CliEnumPropertyAttributes dataType = new CliEnumPropertyAttributes();
		
		public CliEnumPropertyAttributes() {
			super(new CategoryPath(PATH), "PropertyAttributes", 2);
			// TODO: specify CategoryPath, etc.
			String prefix = "";
			add(prefix+"SpecialName", 0x0200);
			add(prefix+"RTSpecialName", 0x0400);
			add(prefix+"HasDefault", 0x1000);
			add(prefix+"Unused", 0xe9ff);
		}
	}

	public static class CliEnumTypeAttributes extends EnumDataType {
		private static final long serialVersionUID = 1L;
		
		/** A statically defined instance.*/
	    public final static CliEnumTypeAttributes dataType = new CliEnumTypeAttributes();
		
		public CliEnumTypeAttributes() {
			super(new CategoryPath(PATH), "TypeAttributes", 4);
			// TODO: specify CategoryPath, etc.
			String prefix = "Visibility_";
			add(prefix+"NotPublic", 0x00000000);
			add(prefix+"Public", 0x00000001);
			add(prefix+"NestedPublic", 0x00000002);
			add(prefix+"NestedPrivate", 0x00000003);
			add(prefix+"NestedFamily", 0x00000004);
			add(prefix+"NestedAssembly", 0x00000005);
			add(prefix+"NestedFamANDAssem", 0x00000006);
			add(prefix+"NestedFamORAssem", 0x00000007);

			prefix = "";
//			add(prefix+"AutoLayout", 0x00000000); // TODO: Will not work, will conflict with Visibility_NotPublic
			add(prefix+"SequentialLayout", 0x00000008);
			add(prefix+"ExplicitLayout", 0x00000010);

//			add(prefix+"Class", 0x00000000); // TODO: Will not work, will conflict with Visibility_NotPublic
			add(prefix+"Interface", 0x00000020);

			add(prefix+"Abstract", 0x00000080);
			add(prefix+"Sealed", 0x00000100);
			add(prefix+"SpecialName", 0x00000400);

			add(prefix+"Import", 0x00001000);
			add(prefix+"Serializable", 0x00002000);

//			add(prefix+"AnsiClass", 0x00000000); // TODO: Will not work, will conflict with Visibility_NotPublic
			add(prefix+"UnicodeClass", 0x00010000);
			add(prefix+"AutoClass", 0x00020000);
			add(prefix+"CustomFormatClass", 0x00030000);

			add(prefix+"CustomStringFormatMask", 0x00C00000);

			add(prefix+"BeforeFieldInit", 0x00100000);

			add(prefix+"RTSpecialName", 0x00000800);
			add(prefix+"HasSecurity", 0x00040000);
			add(prefix+"IsTypeForwarder", 0x00200000);

		}
	}
	
}
