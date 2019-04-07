/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

/**
 * Constants defined in Code View Debug information.
 */
public interface DebugCodeViewConstants {
	/*
	 * * * * * * * * * * * * * * * * * * * *
	 */

	public final static int SIGNATURE_DOT_NET = 0x5253; //RS
	public final static int SIGNATURE_N1      = 0x4e31; //N1
	public final static int SIGNATURE_NB      = 0x4e42; //NB

	public final static int VERSION_09        = 0x3039; //09
	public final static int VERSION_10        = 0x3130; //10
	public final static int VERSION_11        = 0x3131; //11
	public final static int VERSION_12        = 0x3140; //12
	public final static int VERSION_13        = 0x30f0; //13
	public final static int VERSION_DOT_NET   = 0x4453; //DS

	/*
	 * * * * * * * * * * * * * * * * * * * *
	 */

	public final static int sstModule           = 0x120;
	public final static int sstTypes            = 0x121;
	public final static int sstPublic           = 0x122;
	/**publics as symbol (waiting for link)*/
	public final static int sstPublicSym        = 0x123;
	public final static int sstSymbols          = 0x124;
	public final static int sstAlignSym         = 0x125;
	/**because link doesn't emit SrcModule*/
	public final static int sstSrcLnSeg         = 0x126;
	public final static int sstSrcModule        = 0x127;
	public final static int sstLibraries        = 0x128;
	public final static int sstGlobalSym        = 0x129;
	public final static int sstGlobalPub        = 0x12a;
	public final static int sstGlobalTypes      = 0x12b;
	public final static int sstMPC              = 0x12c;
	public final static int sstSegMap           = 0x12d;
	public final static int sstSegName          = 0x12e;
	/**precompiled types*/
	public final static int sstPreComp          = 0x12f;
	/**map precompiled types in global types*/
	public final static int sstPreCompMap       = 0x130;
	public final static int sstOffsetMap16      = 0x131;
	public final static int sstOffsetMap32      = 0x132;
	/**Index of file names*/
	public final static int sstFileIndex        = 0x133;
	public final static int sstStaticSym        = 0x134;

	/**Compile flags symbol*/
	public final static int S_COMPILE    =  0x0001;
	/**Register variable*/
	public final static int S_REGISTER   =  0x0002;
	/**Constant symbol*/
	public final static int S_CONSTANT   =  0x0003;
	/**User defined type*/
	public final static int S_UDT        =  0x0004;
	/**Start Search*/
	public final static int S_SSEARCH    =  0x0005;
	/**Block, procedure, "with" or thunk end*/
	public final static int S_END        =  0x0006;
	/**Reserve symbol space in $$Symbols table*/
	public final static int S_SKIP       =  0x0007;
	/**Reserved symbol for CV internal use*/
	public final static int S_CVRESERVE  =  0x0008;
	/**Path to object file name*/
	public final static int S_OBJNAME    =  0x0009;
	/**End of argument/return list*/
	public final static int S_ENDARG     =  0x000a;
	/**SApecial UDT for cobol that does not symbol pack*/
	public final static int S_COBOLUDT   =  0x000b;
	/**multiple register variable*/
	public final static int S_MANYREG    =  0x000c;
	/**Return description symbol*/
	public final static int S_RETURN     =  0x000d;
	/**Description of this pointer on entry*/
	public final static int S_ENTRYTHIS  =  0x000e;

	/**BP-relative*/
	public final static int S_BPREL16    =  0x0100;
	/**Module-local symbol*/
	public final static int S_LDATA16    =  0x0101;
	/**Global data symbol*/
	public final static int S_GDATA16    =  0x0102;
	/**a public symbol*/
	public final static int S_PUB16      =  0x0103;
	/**Local procedure start*/
	public final static int S_LPROC16    =  0x0104;
	/**Global procedure start*/
	public final static int S_GPROC16    =  0x0105;
	/**Thunk Start*/
	public final static int S_THUNK16    =  0x0106;
	/**block start*/
	public final static int S_BLOCK16    =  0x0107;
	/**With start*/
	public final static int S_WITH16     =  0x0108;
	/**Code label*/
	public final static int S_LABEL16    =  0x0109;
	/**Change execution model*/
	public final static int S_CEXMODEL16 =  0x010a;
	/**Address of virtual function table*/
	public final static int S_VFTABLE16  =  0x010b;
	/**Register relative address*/
	public final static int S_REGREL16   =  0x010c;

	/**BP-relative*/
	public final static int S_BPREL32    =  0x0200;
	/**Module-local symbol*/
	public final static int S_LDATA32    =  0x0201;
	/**Global data symbol*/
	public final static int S_GDATA32    =  0x0202;
	/**a public symbol (CV internal reserved)*/
	public final static int S_PUB32      =  0x0203;
	/**Local procedure start*/
	public final static int S_LPROC32    =  0x0204;
	/**Global procedure start*/
	public final static int S_GPROC32    =  0x0205;
	/**Thunk Start*/
	public final static int S_THUNK32    =  0x0206;
	/**block start*/
	public final static int S_BLOCK32    =  0x0207;
	/**with start*/
	public final static int S_WITH32     =  0x0208;
	/**code label*/
	public final static int S_LABEL32    =  0x0209;
	/**change execution model*/
	public final static int S_CEXMODEL32 =  0x020a;
	/**address of virtual function table*/
	public final static int S_VFTABLE32  =  0x020b;
	/**register relative address*/
	public final static int S_REGREL32   =  0x020c;
	/**local thread storage*/
	public final static int S_LTHREAD32  =  0x020d;
	/**global thread storage*/
	public final static int S_GTHREAD32  =  0x020e;
	/**static link for MIPS EH implementation*/
	public final static int S_SLINK32    =  0x020f;

	/**Local procedure start*/
	public final static int S_LPROCMIPS  =  0x0300;
	/**Global procedure start*/
	public final static int S_GPROCMIPS  =  0x0301;

	/**Reference to a procedure*/
	public final static int S_PROCREF    =  0x0400;
	/**Reference to data*/
	public final static int S_DATAREF    =  0x0401;
	/**Used for page alignment of symbol*/
	public final static int S_ALIGN      =  0x0402;
	/**Maybe reference to a local procedure*/
	public final static int S_LPROCREF   =  0x0403;

	/**Register variable*/
	public final static int S_REGISTER32    = 0x1001;
	/**Constant symbol*/
	public final static int S_CONSTANT32    = 0x1002;
	/**User defined type*/
	public final static int S_UDT32         = 0x1003;
	/**special UDT for cobol that does not symbol pack*/
	public final static int S_COBOLUDT32    = 0x1004;
	/**Multiple register variable*/
	public final static int S_MANYREG32     = 0x1005;
	/**New CV info for BP-relative*/
	public final static int S_BPREL32_NEW   = 0x1006;
	/**New CV info for module-local symbol*/
	public final static int S_LDATA32_NEW   = 0x1007;
	/**New CV info for global data symbol*/
	public final static int S_GDATA32_NEW   = 0x1008;
	/**Newer CV info, defined after 1994*/
	public final static int S_PUBSYM32_NEW  = 0x1009;
	/**New CV info for reference to a local procedure*/
	public final static int S_LPROC32_NEW   = 0x100a;
	/**New CV info for global procedure start*/
	public final static int S_GPROC32_NEW   = 0x100b;
	/**New CV info for address of virtual function table*/
	public final static int S_VFTABLE32_NEW = 0x100c;
	/**New CV info for register relative address*/
	public final static int S_REGREL32_NEW  = 0x100d;
	/**New CV info for local thread storage*/
	public final static int S_LTHREAD32_NEW = 0x100e;
	/**New CV info for global thread storage*/
	public final static int S_GTHREAD32_NEW = 0x100f;
}
