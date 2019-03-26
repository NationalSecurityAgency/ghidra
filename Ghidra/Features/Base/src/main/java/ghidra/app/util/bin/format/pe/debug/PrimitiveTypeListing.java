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

import ghidra.program.model.data.*;
import ghidra.util.Msg;

/**
 * A class to convert from debug data types into Ghidra data types.
 * 
 */
public class PrimitiveTypeListing {

	// Special Types
    /**Uncharacterized type (no type)*/
    public final static short T_NOTYPE    = 0x0000;
    /**Absolute symbol*/
    public final static short T_ABS       = 0x0001;
    /**Segment Type*/
    public final static short T_SEGMENT   = 0x0002;
    /**VOID*/
    public final static short T_VOID      = 0x0003;
    /**Near Pointer to a void*/
    public final static short T_PVOID     = 0x0103;
    /**Far pointer to a void*/
    public final static short T_PFOID     = 0x0203;
    /**Huge pointer to a VOID*/
    public final static short T_PHVOID    = 0x0303;
    /**32-bit near pointer to a void*/
    public final static short T_32PVOID   = 0x0403;
    /**32-bit far pointer to a void*/
    public final static short T_32PFVOID  = 0x0503;
    /**Basic 8-byte currency value*/
    public final static short T_CURRENCY  = 0x0004;
    /**Near basic string*/
    public final static short T_NBASICSTR = 0x0005;
    /**Far basic string*/
    public final static short T_FBASICSTR = 0x0006;
    /**Untranslated type record from Microsoft symbol format*/
    public final static short T_NOTTRANS  = 0x0007;
    /**Bit*/
    public final static short T_BIT       = 0x0060;
    /**Pascal CHAR*/
    public final static short T_PASCHAR   = 0x0061;
	
	// Character Types
    /**8-bit signed*/
    public final static short T_CHAR       = 0x0010;
    /**8-bit unsigned*/
    public final static short T_UCHAR      = 0x0020;
    /**Near pointer to 8-bit signed*/
    public final static short T_PCHAR      = 0x0110;
    /**Near pointer to 8-bit unsigned*/
    public final static short T_PUCHAR	   = 0x0120;
    /**Far pointer to 8-bit signed*/
    public final static short T_PFCHAR	   = 0x0210;
    /**Far pointer to 8-bit unsigned*/
    public final static short T_PFUCHAR	   = 0x0220;
    /**Huge pointer to 8-bit signed*/
    public final static short T_PHCHAR	   = 0x0310;
    /**Huge pointer to 8-bit unsigned*/
    public final static short T_PHUCHAR	   = 0x0320;
    /**16:32 near pointer to 8-bit signed*/
    public final static short T_32PCHAR	   = 0x0410;
    /**16:32 near pointer to 8-bit unsigned*/
    public final static short T_32PUCHAR   = 0x0420;
    /**16:32 far pointer to 8-bit signed*/
    public final static short T_32PFCHAR   = 0x0510;
    /**16:32 far pointer to 8-bit unsigned*/
    public final static short T_32PFUCHAR  = 0x0520;
	
	// Real Character Types
    /**Real char*/
    public final static short T_RCHAR	  = 0x0070;
    /**Near pointer to a real char*/
    public final static short T_PRCHAR    = 0x0170;
    /**Far pointer to a real char*/
    public final static short T_PFRCHAR   = 0x0270;
    /**Huge pointer to a real char*/
    public final static short T_PHRCHAR   = 0x0370;
    /**16:32 near pointer to a real char*/
    public final static short T_32PRCHAR  = 0x0470;
    /**16:32 far pointer to a real char*/
    public final static short T_32PFRCHAR = 0x0570;

	// Wide Character Types
    /**wide char*/
    public final static short T_WCHAR     = 0x0071;
    /**Near pointer to a wide char*/
    public final static short T_PWCHAR    = 0x0171;
    /**far pointer to a wide char*/
    public final static short T_PFWCHAR   = 0x0271;
    /**Huge pointer to a wide char*/
    public final static short T_PHWCHAR   = 0x0371;
    /**16:32 near pointer to a wide char*/
    public final static short T_32PWCHAR  = 0x0471;
    /**16:32 far pointer to a wide char*/
    public final static short T_32PFWCHAR = 0x0571;

	// Real 16-bit Integer Types
    /**Real 16-bit signed short*/
    public final static short T_INT2 	  = 0x0072;
    /**Real 16-bit unsigned short*/
    public final static short T_UINT2 	  = 0x0073;
    /**Near pointer to 16-bit signed short*/
    public final static short T_PINT2 	  = 0x0172;
    /**Near pointer to 16-bit unsigned short*/
    public final static short T_PUINT2 	  = 0x0173;
    /**Far pointer to 16-bit signed short*/
    public final static short T_PFINT2 	  = 0x0272;
    /**Far point to  16-bit unsigned short*/
    public final static short T_PFUINT2   = 0x0273;
    /**Huge pointer to 16-bit signed short*/
    public final static short T_PHINT2    = 0x0372;
    /**Huge pointer to 16-bit unsigned short*/
    public final static short T_PHUINT2   = 0x0373;
    /**16:32 near pointer to 16-bit signed short*/
    public final static short T_32PINT2   = 0x0472;
    /**16:32 near pointer to 16-bit unsigned short*/
    public final static short T_32PUINT2  = 0x0473;
    /**16:32 far pointer to 16-bit signed short*/
    public final static short T_32PFINT2  = 0x0572;
    /**16:32 far pointer to 16-bit unsigned short*/
    public final static short T_32PFUINT2 = 0x0573;
	
	// 16-bit Short Types
    /**16-bit signed*/
    public final static short T_SHORT      = 0x0011;
    /**16-bit unsigned*/
    public final static short T_USHORT     = 0x0021;
    /**Near pointer to 16-bit signed*/
    public final static short T_PSHORT     = 0x0111;
    /**Near pointer to 16-bit unsigned*/
    public final static short T_PUSHORT    = 0x0121;
    /**Far pointer to16-bit signed*/
    public final static short T_PFSHORT    = 0x0211;
    /**Far pointer to 16-bit unsigned*/
    public final static short T_PFUSHORT   = 0x0221;
    /**Huge pointer to 16-bit signed*/
    public final static short T_PHSHORT    = 0x0311;
    /**Huge pointer 16-bit unsigned*/
    public final static short T_PHUSHORT   = 0x0321;
    /**16:32 near pointer to 16-bit signed*/
    public final static short T_32PSHORT   = 0x0411;
    /**16:32 near pointer to 16-bit unsigned*/
    public final static short T_32PUSHORT  = 0x0421;
    /**16:32 far pointer to 16-bit signed*/
    public final static short T_32PFSHORT  = 0x0511;
    /**16:32 far pointer to 16-bit unsigned*/
    public final static short T_32PFUSHORT = 0x0521;
	
	// Real 32-bit Integer Types
    /**Real 32-bit signed short*/
    public final static short T_INT4      = 0x0074;
    /**Real 32-bit unsigned short*/
    public final static short T_UINT4 	  = 0x0075;
    /**Near pointer to 32-bit signed short*/
    public final static short T_PINT4 	  = 0x0174;
    /**Near pointer to 32-bit unsigned short*/
    public final static short T_PUINT4 	  = 0x0175;
    /**Far pointer to 32-bit signed short*/
    public final static short T_PFINT4 	  = 0x0274;
    /**Far pointer to 32-bit unsigned short*/
    public final static short T_PFUINT4   = 0x0275;
    /**Huge pointer to 32-bit signed short*/
    public final static short T_PHINT4    = 0x0374;
    /**Huge pointer to 32-bit unsigned short*/
    public final static short T_PHUINT4   = 0x0375;
    /**16:32 near pointer to 32-bit signed short*/
    public final static short T_32PINT4   = 0x0474;
    /**16:32 near pointer to 32-bit unsigned short*/
    public final static short T_32PUINT4  = 0x0475;
    /**16:32 far pointer to 32-bit signed short*/
    public final static short T_32PFINT4  = 0x0574;
    /**16:32 far pointer to 32-bit unsigned short*/
    public final static short T_32PFUINT4 = 0x0575;
	
	// 32-bit Long Types
    /**32-bit signed*/
    public final static short T_LONG 	  = 0x0012;
    /**32-bit unsigned*/
    public final static short T_ULONG 	  = 0x0022;
    /**Near pointer to 32-bit signed*/
    public final static short T_PLONG 	  = 0x0112;
    /**Near Pointer to 32-bit unsigned*/
    public final static short T_PULONG 	  = 0x0122;
    /**Far pointer to 32-bit signed*/
    public final static short T_PFLONG 	  = 0x0212;
    /**Far pointer to 32-bit unsigned*/
    public final static short T_PFULONG   = 0x0222;
    /**Huge pointer to 32-bit signed*/
    public final static short T_PHLONG 	  = 0x0312;
    /**Huge pointer to 32-bit unsigned*/
    public final static short T_PHULONG   = 0x0322;
    /**16:32 near pointer to 32-bit signed*/
    public final static short T_32PLONG   = 0x0412;
    /**16:32 near pointer to 32-bit unsigned*/
    public final static short T_32PULONG  = 0x0422;
    /**16:32 far pointer to 32-bit signed*/
    public final static short T_P2PFLONG  = 0x0512;
    /**16:32 far pointer to 32-bit unsigned*/
    public final static short T_32PFULONG = 0x0522;
	
	// Real 64-bit short Types
    /**64-bit signed*/
    public final static short T_INT8 	  = 0x0076;
    /**64-bit unsigned*/
    public final static short T_UINT8 	  = 0x0077;
    /**Near pointer to 64-bit signed*/
    public final static short T_PINT8 	  = 0x0176;
    /**Near Pointer to 64-bit unsigned*/
    public final static short T_PUINT8 	  = 0x0177;
    /**Far pointer to 64-bit signed*/
    public final static short T_PFINT8 	  = 0x0276;
    /**Far pointer to 64-bit unsigned*/
    public final static short T_PFUINT8   = 0x0277;
    /**Huge pointer to 64-bit signed*/
    public final static short T_PHINT8 	  = 0x0376;
    /**Huge pointer to 64-bit unsigned*/
    public final static short T_PHUINT8   = 0x0377;
    /**16:32 near pointer to 64-bit signed*/
    public final static short T_32PINT8   = 0x0476;
    /**16:32 near pointer to 64-bit unsigned*/
    public final static short T_32PUINT8  = 0x0477;
    /**16:32 far pointer to 64-bit signed*/
    public final static short T_32PFINT8  = 0x0576;
    /**16:32 far pointer to 64-bit unsigned*/
    public final static short T_32PFUINT8 = 0x0577;
		
	// 64-bit Integral Types
    /**64-bit signed*/
    public final static short T_QUAD 	  = 0x0013;
    /**64-bit unsigned*/
    public final static short T_UQUAD 	  = 0x0023;
    /**Near pointer to 64-bit signed*/
    public final static short T_PQUAD 	  = 0x0113;
    /**Near pointer to 64-bit unsigned*/
    public final static short T_PUQUAD 	  = 0x0123;
    /**Far pointer to 64-bit signed*/
    public final static short T_PFQUAD 	  = 0x0213;
    /**Far pointer to 64-bit unsigned*/
    public final static short T_PFUQUAD   = 0x0223;
    /**Huge pointer to 64-bit signed*/
    public final static short T_PHQUAD 	  = 0x0313;
    /**Huge pointer to 64-bit unsigned*/
    public final static short T_PHUQUAD   = 0x0323;
    /**16:32 near pointer to 64-bit signed*/
    public final static short T_32PQUAD   = 0x0413;
    /**16:32 near pointer to 64-bit unsigned*/
    public final static short T_32PUQUAD  = 0x0423;
    /**16:32 far pointer to 64-bit signed*/
    public final static short T_32PFQUAD  = 0x0513;
    /**16:32 far pointer to 64-bit unsigned*/
    public final static short T_32PFUQUAD = 0x0523;
	
	// 32-bit Real Types
    /**32-bit real*/
    public final static short T_REAL32     = 0x0040;
    /**Near pointer to 32-bit real*/
    public final static short T_PREAL32    = 0x0140;
    /**Far pointer to 32-bit real*/
    public final static short T_PFREAL32   = 0x0240;
    /**Huge pointer to 32-bit real*/
    public final static short T_PHREAL32   = 0x0340;
    /**16:32 near pointer to 32-bit real*/
    public final static short T_32PREAL32  = 0x0440;
    /**16:32 far pointer to 32-bit real*/
    public final static short T_32PFREAL32 = 0x0540;
	
	// 64-bit Real Types
    /**64-bit real*/
    public final static short T_REAL64     = 0x0041;
    /**Near pointer to 64-bit real*/
    public final static short T_PREAL64    = 0x0141;
    /**Far pointer to 64-bit real*/
    public final static short T_PFREAL64   = 0x0241;
    /**Huge pointer to 64-bit real*/
    public final static short T_PHREAL64   = 0x0341;
    /**16:32 near pointer to 64-bit real*/
    public final static short T_32PREAL64  = 0x0441;
    /**16:32 far pointer to 64-bit real*/
    public final static short T_32PFREAL64 = 0x0541;
	
	// 32-bit Complex Types
    /**32-bit complex*/
    public final static short T_CPLX32     = 0x0050;
    /**Near pointer to 32-bit complex*/
    public final static short T_PCPLX32    = 0x0150;
    /**Far pointer to 32-bit complex*/
    public final static short T_PFCPLX32   = 0x0250;
    /**Huge pointer to 32-bit complex*/
    public final static short T_PHCPLX32   = 0x0350;
    /**16:32 near pointer to 32-bit complex*/
    public final static short T_32PCPLX32  = 0x0450;
    /**16:32 far pointer to 32-bit complex*/
    public final static short T_32PFCPLX32 = 0x0550;
	
	//64-bit Complex Types
    /**32-bit complex*/
    public final static short T_CPLX64     = 0x0051;
    /**Near pointer to 64-bit complex*/
    public final static short T_PCPLX64    = 0x0151;
    /**Far Pointer to 64-bit complex*/
    public final static short T_PFCPLX64   = 0x0251;
    /**Huge pointer to 64-bit complex*/
    public final static short T_PHCPLX64   = 0x0351;
    /**16:32 near pointer to 64-bit complex*/
    public final static short T_32PCPLX64  = 0x0451;
    /**16:32 far pointer to 64-bit complex*/
    public final static short T_32PFCPLX64 = 0x0551;
	
	// Boolean Types
    /**8-bit boolean*/
    public final static short T_BOOL08     = 0x0030;
    /**16-bit boolean*/
    public final static short T_BOOL16     = 0x0031;
    /**32-bit boolean*/
    public final static short T_BOOL32     = 0x0032;
    /**64-bit boolean*/
    public final static short T_BOOL64     = 0x0033;
    /**Near pointer to 8-bit boolean*/
    public final static short T_PBOOL08    = 0x0130;
    /**Near pointer to 16-bit boolean*/
    public final static short T_PBOOL16    = 0x0131;
    /**Near pointer to 32-bit boolean*/
    public final static short T_PBOOL32    = 0x0132;
    /**Near pointer to 64-bit boolean*/
    public final static short T_PBOOL64    = 0x0133;
    /**Far Pointer to 8-bit boolean*/
    public final static short T_PFBOOL08   = 0x0230;
    /**Far Pointer to 16-bit boolean*/
    public final static short T_PFBOOL16   = 0x0231;
    /**Far Pointer to 32-bit boolean*/
    public final static short T_PFBOOL32   = 0x0232;
    /**Far Pointer to 64-bit boolean*/
    public final static short T_PFBOOL64   = 0x0233;
    /**Huge pointer to 8-bit boolean*/
    public final static short T_PHBOOL08   = 0x0330;
    /**Huge pointer to 16-bit boolean*/
    public final static short T_PHBOOL16   = 0x0331;
    /**Huge pointer to 32-bit boolean*/
    public final static short T_PHBOOL32   = 0x0332;
    /**Huge pointer to 64-bit boolean*/
    public final static short T_PHBOOL64   = 0x0333;
    /**16:32 near pointer to 8-bit boolean*/
    public final static short T_32PBOOL08  = 0x0430;
    /**16:32 near pointer to 16-bit boolean*/
    public final static short T_32PBOOL16  = 0x0431;
    /**16:32 near pointer to 32-bit boolean*/
    public final static short T_32PBOOL32  = 0x0432;
    /**16:32 near pointer to 64-bit boolean*/
    public final static short T_32PBOOL64  = 0x0433;
    /**16:32 far pointer to 8-bit boolean*/
    public final static short T_32PFBOOL08 = 0x0530;
    /**16:32 far pointer to 16-bit boolean*/
    public final static short T_32PFBOOL16 = 0x0531;
    /**16:32 far pointer to 32-bit boolean*/
    public final static short T_32PFBOOL32 = 0x0532;
    /**16:32 far pointer to 64-bit boolean*/
    public final static short T_32PFBOOL64 = 0x0533;
	
    /**HANDLE*/
    public final static short T_HINSTANCE = 0x10fd;

	public static DataType getDataType(short type) {

		switch (type) {
			case T_SHORT :
			case T_USHORT :
				return new WordDataType();
			case T_PSHORT :
			case T_PUSHORT :
			case T_PFSHORT :
			case T_PFUSHORT :
			case T_PHSHORT :
			case T_PHUSHORT :
			case T_32PSHORT :
			case T_32PUSHORT :
			case T_32PFSHORT :
			case T_32PFUSHORT :
				return new Pointer32DataType(new WordDataType());
			case T_INT8 :
			case T_UINT8 :
				return new QWordDataType();
			case T_PINT8 :
			case T_PUINT8 :
			case T_PFINT8 :
			case T_PFUINT8 :
			case T_PHINT8 :
			case T_PHUINT8 :
			case T_32PINT8 :
			case T_32PUINT8 :
			case T_32PFINT8 :
			case T_32PFUINT8 :
				return new Pointer32DataType(new QWordDataType());
			case T_INT4 :
			case T_UINT4 :
				return new DWordDataType();
			case T_PINT4 :
			case T_PUINT4 :
			case T_PFINT4 :
			case T_PFUINT4 :
			case T_PHINT4 :
			case T_PHUINT4 :
			case T_32PINT4 :
			case T_32PUINT4 :
			case T_32PFINT4 :
			case T_32PFUINT4 :
				return new Pointer32DataType(new DWordDataType());
			case T_LONG :
			case T_ULONG :
				return new DWordDataType();
			case T_PLONG :
			case T_PULONG :
			case T_PFLONG :
			case T_PFULONG :
			case T_PHLONG :
			case T_PHULONG :
			case T_32PLONG :
			case T_32PULONG :
			case T_P2PFLONG :
			case T_32PFULONG :
				return new Pointer32DataType(new DWordDataType());
			case T_QUAD :
			case T_UQUAD :
				return new QWordDataType();
			case T_PQUAD :
			case T_PUQUAD :
			case T_PFQUAD :
			case T_PFUQUAD :
			case T_PHQUAD :
			case T_PHUQUAD :
			case T_32PQUAD :
			case T_32PUQUAD :
			case T_32PFQUAD :
			case T_32PFUQUAD :
				return new Pointer32DataType(new QWordDataType());
			case T_REAL32 :
			case T_PREAL32 :
				return new FloatDataType();
			case T_PFREAL32 :
			case T_PHREAL32 :
			case T_32PREAL32 :
			case T_32PFREAL32 :
				return new Pointer32DataType(new FloatDataType());
			case T_REAL64 :
			case T_PREAL64 :
				return new DoubleDataType();
			case T_PFREAL64 :
			case T_PHREAL64 :
			case T_32PREAL64 :
			case T_32PFREAL64 :
				return new Pointer32DataType(new DoubleDataType());
			case T_32PVOID:
				return new TypedefDataType("VOID", new Pointer32DataType());
			case T_BOOL08 :
				return new TypedefDataType("bool08", new ByteDataType());
			case T_BOOL16 :
				return new TypedefDataType("bool16", new WordDataType());
			case T_BOOL32 :
				return new TypedefDataType("bool32", new DWordDataType());
			case T_BOOL64 :
				return new TypedefDataType("bool32", new QWordDataType());
			case T_HINSTANCE :
				return new TypedefDataType("HINSTANCE", new Pointer32DataType());
			case T_CHAR :
			case T_UCHAR :
				return new CharDataType();
			case T_PCHAR :
			case T_PUCHAR :
			case T_PFCHAR :
			case T_PFUCHAR :
			case T_PHCHAR :
			case T_PHUCHAR :
			case T_32PCHAR :
			case T_32PUCHAR :
			case T_32PFCHAR :
			case T_32PFUCHAR :
				return new Pointer32DataType(new CharDataType());
			case T_RCHAR :
				return new CharDataType();
			case T_PRCHAR :
			case T_PFRCHAR :
			case T_PHRCHAR :
			case T_32PRCHAR :
			case T_32PFRCHAR :
				return new Pointer32DataType(new CharDataType());
			case T_WCHAR :
				return new UnicodeDataType();
			case T_PWCHAR :
			case T_PFWCHAR :
			case T_PHWCHAR :
			case T_32PWCHAR :
			case T_32PFWCHAR :
				return new Pointer32DataType(new UnicodeDataType());
			default :
//TODO: unknown types??
			    Msg.warn(PrimitiveTypeListing.class, "PrimitiveTypeListing: unrecognized  data type ["
                        + "] - 0x" + Integer.toHexString(type));
				return DataType.DEFAULT;
		}
	}
	
		
}
