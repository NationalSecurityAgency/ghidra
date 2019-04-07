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
package ghidra.app.util.bin.format.xcoff;

public final class XCoffSymbolStorageClassCSECT {

	/* csect storage class, in x_smlas.  */
	public final static int XMC_PR = 0;		/* program code */
	public final static int XMC_RO = 1;		/* read only constant */
	public final static int XMC_DB = 2;		/* debug dictionary table */
	public final static int XMC_TC = 3;		/* general TOC entry */
	public final static int XMC_UA = 4;		/* unclassified */
	public final static int XMC_RW = 5;		/* read/write data */
	public final static int XMC_GL = 6;		/* global linkage */
	public final static int XMC_XO = 7;		/* extended operation */
	public final static int XMC_SV = 8;		/* 32-bit supervisor call descriptor csect */
	public final static int XMC_BS = 9;		/* BSS class (uninitialized static internal) */
	public final static int XMC_DS = 10;	/* csect containing a function descriptor */
	public final static int XMC_UC = 11;	/* unnamed FORTRAN common */
	public final static int XMC_TI = 12;	/* reserved */
	public final static int XMC_TB = 13;	/* reserved */
	public final static int XMC_TC0 = 15;	/* TOC anchor for TOC addressability */
	public final static int XMC_TD = 16;	/* scalar data entry in TOC */
	public final static int XMC_SV64 = 17;	/* 64-bit supervisor call descriptor csect */
	public final static int XMC_SV3264 = 18;/* supervisor call descriptor csect for both 32-bit and 64-bit */

}
