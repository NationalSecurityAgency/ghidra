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
// Calculate false positive/negative statistics given "marked" programs
//@category FunctionID
import java.io.*;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.db.FidQueryService;
import ghidra.feature.fid.service.*;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.ProgramContentHandler;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;

/**
 * Runs through recursively through a set of folders provided by the user.
 * Programs are assumed to be "marked", meaning that functions all have their correct labels.
 * Each function in each program is searched within the active FID databases and various statistics
 * are calculated.
 *    1) Match found/not found
 *    2) Are any matches found correct (as compared to existing symbol)
 *    3) Are there multiple potential matches (whether correct or not)
 *
 * If program symbols are mangled, this script assumes the primary symbol is not demangled.
 */
public class FidStatistics extends GhidraScript {

	private StatRecord statRecord;
	private FidService service;
	private MatchNameAnalysis matchAnalysis;
	private FileWriter highFalsePositive;			// Incorrect matches that scored high
	private FileWriter lowTruePositive;				// Correct matches that score low
	private TreeSet<SymbolPair> equivSymbols;
	private float scoreThreshold;

	public static class SymbolPair implements Comparable<SymbolPair> {

		private String sym1;
		private String sym2;
		
		public SymbolPair(String a,String b) {
			sym1 = a;
			sym2 = b;
		}

		@Override
		public int compareTo(SymbolPair o) {
			int val = sym1.compareTo(o.sym1);
			if (val != 0) return val;
			return sym2.compareTo(o.sym2);
		}
		
	}

	public static class MatchRecord {
		private String progName;
		private String funcName;
		private String matchName;
		private long fullHash;
		private long address;
		private float score;
		private float childScore;
		private float parentScore;

		public MatchRecord(FidSearchResult result,String finalMatchName,boolean isFalse) {
			this.progName = result.function.getProgram().getDomainFile().getPathname();
			this.fullHash = result.hashQuad.getFullHash();
			this.funcName = result.function.getName();
			this.matchName = finalMatchName;
			this.address = result.function.getEntryPoint().getOffset();
			FidMatch fidMatch = result.matches.get(0);
			this.score = fidMatch.getOverallScore();
			this.childScore = fidMatch.getChildFunctionCodeUnitScore();
			this.parentScore = fidMatch.getParentFunctionCodeUnitScore();
		}

		public void print(StringBuilder buf) {
			buf.append("score= ");
			buf.append(score);
			buf.append(" fh=0x");
			buf.append(Long.toHexString(fullHash));
			buf.append(" child=").append(childScore);
			buf.append(" par=").append(parentScore);
			buf.append(" address=");
			buf.append(Long.toHexString(address));
			buf.append(" name=");
			buf.append(funcName);
			buf.append(" prog=");
			buf.append(progName);
			if (matchName != null) {
				buf.append(" match=");
				buf.append(matchName);
			}
//			if (isFalsePositive)
//				buf.append("  FALSE");
		}
	}

	public static class StatRecord {
		public int totalFunction;
		public int matchUniquely;
		public int matchMultiply;
		public int noMatch;
		public int nameMatched;
		public int falsePositive;
		
		public StatRecord() {
			totalFunction = 0;
			matchUniquely = 0;
			matchMultiply = 0;
			noMatch = 0;
			nameMatched = 0;
			falsePositive = 0;
		}

		public static void indent(StringBuilder buf,String last) {
			for(int i=last.length();i<10;++i)
				buf.append(' ');
		}

		public void print(StringBuilder buf) {
			String str = Integer.toString(totalFunction);
			buf.append(str);
			indent(buf,str);
			str = Integer.toString(noMatch);
			buf.append(str);
			indent(buf,str);
			str = Integer.toString(matchUniquely+matchMultiply);
			buf.append(str);
			indent(buf,str);
			str = '(' + Integer.toString(matchUniquely) + ',' + Integer.toString(matchMultiply) + ')';
			buf.append(str);
			indent(buf,str);
			str = Integer.toString(nameMatched);
			buf.append(str);
			indent(buf,str);
			str = Integer.toString(falsePositive);
			buf.append(str);
		}
		
		public static String getColumns() {
			return "Total     No Match  Hits      uniq/mult N-Match   False";
		}
	}

	private void addEquivSymbols(String a,String b) {
		SymbolPair pair = new SymbolPair(a,b);
		equivSymbols.add(pair);
		pair = new SymbolPair(b,a);
		equivSymbols.add(pair);
	}

	private void initialize() {
		statRecord = new StatRecord();
		service = new FidService();
		matchAnalysis = new MatchNameAnalysis();
		equivSymbols = new TreeSet<SymbolPair>();
		addEquivSymbols("entry","_WinMainCRTStartup");
		addEquivSymbols("__alloca_probe","__chkstk");
		addEquivSymbols("_strncpy_s_downlevel","_strncpy_s");
		addEquivSymbols("_strcpy_s_downlevel","_strcpy_s");
		addEquivSymbols("strcat_s_downlevel", "strcat_s");
		addEquivSymbols("_memcpy_s_downlevel","_memcpy_s");
		addEquivSymbols("_memmove_s_downlevel", "_memmove_s");
		addEquivSymbols("__ftol2_downlevel","__ftol2");
		addEquivSymbols("_wmakepath_s_downlevel", "_wmakepath_s");
		addEquivSymbols("entry", "_wWinMainCRTStartup");
		addEquivSymbols("entry", "_wmainCRTStartup");
		addEquivSymbols("entry", "_mainCRTStartup");
		addEquivSymbols("entry","__DllMainCRTStartup@12");
		addEquivSymbols("_errno", "__doserrno");
		addEquivSymbols("?StringCchCopyW@@YGJPAGIPBG@Z","_StringCchCopyW@12");
		addEquivSymbols("_StringCchCopyNW@16", "?StringCchCopyNW@@YGJPAGIPBGI@Z");
		addEquivSymbols("_StringCchLengthW@12","?StringCchLengthW@@YGJPB_WIPAI@Z");
		addEquivSymbols("_StringCchLengthA@12", "?StringCchLengthA@@YGJPBDIPAI@Z");
		addEquivSymbols("_RtlStringCchCopyW@12","=_StringCchCopyW@12");
		addEquivSymbols("?RtlStringCchCopyW@@YGJPAGIPBG@Z","_StringCchCopyA@12");
		addEquivSymbols("_RtlStringCchCopyW@12","_StringCchCopyW@12");
		addEquivSymbols("_RtlStringCchCopyNW@16", "?StringCchCopyNW@@YGJPAGIPBGI@Z");
		addEquivSymbols("?RtlStringCchLengthW@@YGJPBGIPAI@Z", "?StringCchLengthW@@YGJPB_WIPAI@Z");
		addEquivSymbols("_RtlStringCchLengthW@12", "?StringCchLengthW@@YGJPB_WIPAI@Z");
		addEquivSymbols("?RtlStringCchCatW@@YGJPAGIPBG@Z", "_StringCchCatA@12");
		addEquivSymbols("?StringCchCatW@@YGJPAGIPBG@Z", "_StringCchCatA@12");
		addEquivSymbols("_StringCchCatW@12", "_StringCchCatA@12");
		addEquivSymbols("?StringCchCopyW@@YGJPAGIPBG@Z","_StringCchCopyA@12");
		addEquivSymbols("?ULongLongToUInt@@YGJ_KPAI@Z","_ULongLongToULong@12");
		addEquivSymbols("_ULongLongToUInt@12","_ULongLongToULong@12");
		addEquivSymbols("_ULongLongToUInt@12","_ULongLongToULong@12");
		addEquivSymbols("?ULongLongToULong@@YGJ_KPAK@Z","_ULongLongToULong@12");
		addEquivSymbols("_RtlULongLongToULong@12", "_ULongLongToULong@12");
		addEquivSymbols("_RtlULongLongToUInt@12", "_ULongLongToULong@12");
		addEquivSymbols("?RtlULongLongToULong@@YGJ_KPAK@Z", "_ULongLongToULong@12");
		addEquivSymbols("?ULongPtrAdd@@YGJKKPAK@Z", "_ULongAdd@12");
		addEquivSymbols("_ULongAdd@12","?ULongAdd@@YGJKKPAK@Z");
		addEquivSymbols("_ULongAdd@12","?SizeTAdd@@YGJIIPAI@Z");
		addEquivSymbols("_ULongAdd@12","?UIntAdd@@YGJIIPAI@Z");
		addEquivSymbols("_ULongAdd@12","?SIZETAdd@@YGJKKPAK@Z");
		addEquivSymbols("_RtlULongAdd@12","?RtlULongAdd@@YGJKKPAK@Z");
		addEquivSymbols("_RtlSIZETAdd@12","?RtlULongAdd@@YGJKKPAK@Z");
		addEquivSymbols("_UIntAdd@12","_ULongAdd@12");
		addEquivSymbols("LoadStringA","LoadStringW");
		addEquivSymbols("_StringCchCopyW@12", "_StringCchCopyA@12");
		addEquivSymbols("?StringCchCopyA@@YGJPADIPBD@Z","_StringCchCopyA@12");
		addEquivSymbols("StringCchVPrintfA","StringCchVPrintfW");
		addEquivSymbols("?StringCchCatW@@YGJPAGIPBG@Z", "_StringCchCatW@12");
		addEquivSymbols("__safecrt_fassign", "__fassign_l");
		addEquivSymbols("?StringLengthWorkerW@@YGJPBGIPAI@Z","_StringLengthWorkerW@12");
		addEquivSymbols("?StringCatWorkerW@@YGJPAGIPBG@Z", "_StringCatWorkerW@12");
		addEquivSymbols("_decode_aligned_offset_block@12","_decode_verbatim_block@12");
		addEquivSymbols("??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@V_STL70@@@std@@QAE@ABV01@@Z",
						"??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@ABV01@@Z");
		addEquivSymbols("??0?$CSimpleStringT@G$0A@@ATL@@QAE@PBGHPAUIAtlStringMgr@1@@Z",
						"??0?$CSimpleStringT@_W$0A@@ATL@@QAE@PB_WHPAUIAtlStringMgr@1@@Z");
		addEquivSymbols("_NFMdeco_destroy@8","_NFMcomp_destroy@8");
		addEquivSymbols("_StringCchVPrintfW@16","?StringCchVPrintfW@@YGJPAGIPBGPAD@Z");
		addEquivSymbols("_StringCbVPrintfA@16","?StringCchVPrintfW@@YGJPAGIPBGPAD@Z");
		addEquivSymbols("?StringCchPrintfA@@YAJPADIPBDZZ", "?StringCchPrintfW@@YAJPAGIPBGZZ");
		addEquivSymbols("_StringCchPrintfW","?StringCchPrintfW@@YAJPAGIPBGZZ");
		addEquivSymbols("_StringCbPrintfA","?StringCchPrintfW@@YAJPAGIPBGZZ");
		addEquivSymbols("?AtlA2WHelper@@YGPAGPAGPBDH@Z","?AfxA2WHelper@@YGPA_WPA_WPBDH@Z");
		addEquivSymbols("??0?$CSimpleStringT@G$0A@@ATL@@QAE@PAUIAtlStringMgr@1@@Z",
						"??0?$CSimpleStringT@D$0A@@ATL@@QAE@PAUIAtlStringMgr@1@@Z");
		addEquivSymbols("_RtlStringCchCopyA@12","?StringCchCopyA@@YGJPADIPBD@Z");
		addEquivSymbols("??0?$CStringT@GV?$StrTraitATL@GV?$ChTraitsCRT@G@ATL@@@ATL@@@ATL@@QAE@PBGHPAUIAtlStringMgr@1@@Z",
						"??0?$CStringT@DV?$StrTraitMFC@DV?$ChTraitsCRT@D@ATL@@@@@ATL@@QAE@PBDHPAUIAtlStringMgr@1@@Z");
		addEquivSymbols("??0?$CSimpleStringT@G$0A@@ATL@@QAE@ABV01@@Z","??0?$CSimpleStringT@D$0A@@ATL@@QAE@ABV01@@Z");
		addEquivSymbols("??0?$CStringT@GV?$StrTraitATL@GV?$ChTraitsCRT@G@ATL@@@ATL@@@ATL@@QAE@PBGPAUIAtlStringMgr@1@@Z",
						"??0?$CStringT@DV?$StrTraitMFC@DV?$ChTraitsCRT@D@ATL@@@@@ATL@@QAE@PB_WPAUIAtlStringMgr@1@@Z");
		addEquivSymbols("??0?$CStringT@GV?$StrTraitATL@GV?$ChTraitsCRT@G@ATL@@@ATL@@@ATL@@QAE@ABV01@@Z",
						"??0?$CStringT@DV?$StrTraitMFC@DV?$ChTraitsCRT@D@ATL@@@@@ATL@@QAE@ABV01@@Z");
		addEquivSymbols("__ltoa_s_downlevel","__ltow_s");
		addEquivSymbols("??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@V_STL70@@@std@@QAE@XZ",
						"??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@XZ");
		addEquivSymbols("_StringCchPrintfA","?StringCchPrintfW@@YAJPAGIPBGZZ");
		addEquivSymbols("?StringCbPrintfA@@YAJPADIPBDZZ", "?StringCchPrintfW@@YAJPAGIPBGZZ");
		addEquivSymbols("?ULongMult@@YGJKKPAK@Z", "_ULongMult@12");
		addEquivSymbols("?_Getwctypes@@YAPB_WPB_W0PAFPBU_Ctypevec@@@Z", "__Getwctypes");
		addEquivSymbols("?_Getwctype@@YAF_WPBU_Ctypevec@@@Z", "__Getwctype");
		addEquivSymbols("?_Getwctype@@YAF_WPEBU_Ctypevec@@@Z", "_Getwctype");
		addEquivSymbols("?AtlW2AHelper@@YGPADPADPBGH@Z", "?AfxW2AHelper@@YGPADPADPB_WH@Z");
		addEquivSymbols("??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@V_STL70@@@std@@QAE@ID@Z",
						"??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@ID@Z");
		addEquivSymbols("?StringCchPrintfA@@YAJPADIPBDZZ","?StringCbPrintfA@@YAJPADIPBDZZ");
		addEquivSymbols("??0?$CStringT@DV?$StrTraitATL@DV?$ChTraitsCRT@D@ATL@@@ATL@@@ATL@@QAE@PBDHPAUIAtlStringMgr@1@@Z",
						"??0?$CStringT@DV?$StrTraitMFC@DV?$ChTraitsCRT@D@ATL@@@@@ATL@@QAE@PBDHPAUIAtlStringMgr@1@@Z");
		addEquivSymbols("_wmemcpy_s","?CopyCharsOverlapped@?$CSimpleStringT@_W$0A@@ATL@@SAXPA_WIPB_WH@Z");
		addEquivSymbols("?StringCbCopyA@@YGJPADIPBD@Z","_StringCbCopyA@12");
		addEquivSymbols("??0?$basic_string@GU?$char_traits@G@std@@V?$allocator@G@2@V_STL70@@@std@@QAE@IG@Z",
						"??0?$basic_string@GU?$char_traits@G@std@@V?$allocator@G@2@@std@@QAE@IG@Z");
		addEquivSymbols("??1?$basic_string@GU?$char_traits@G@std@@V?$allocator@G@2@@std@@QEAA@XZ",
			"??1?$basic_string@GU?$char_traits@G@std@@V?$allocator@G@2@V_STL70@@@std@@QEAA@XZ");
		addEquivSymbols("?CopyChars@?$CSimpleStringT@G$0A@@ATL@@SAXPAGIPBGH@Z",
						"?CopyCharsOverlapped@?$CSimpleStringT@_W$0A@@ATL@@SAXPA_WIPB_WH@Z");
		addEquivSymbols("??0?$CStringT@GV?$StrTraitATL@GV?$ChTraitsCRT@G@ATL@@@ATL@@@ATL@@QAE@PBGPAUIAtlStringMgr@1@@Z",
						"??0?$CStringT@DV?$StrTraitMFC@DV?$ChTraitsCRT@D@ATL@@@@@ATL@@QAE@PB_WPAUIAtlStringMgr@1@@Z");
		addEquivSymbols("wcscpy_s_downlevel", "wcscpy_s");
		addEquivSymbols("_StringCbCopyA@12", "_StringCchCopyA@12");
		addEquivSymbols("_wcscat_s_downlevel", "_wcscat_s");
		addEquivSymbols("??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@V_STL70@@@std@@QAE@PBD@Z",
						"??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@PBD@Z");
		addEquivSymbols("?_Towupper@@YA_W_WPBU_Ctypevec@@@Z", "__Towupper");
		addEquivSymbols("?_Towlower@@YA_W_WPBU_Ctypevec@@@Z", "__Towlower");
		addEquivSymbols("?_Towupper@@YA_W_WPEBU_Ctypevec@@@Z", "_Towupper");
		addEquivSymbols("?_Towlower@@YA_W_WPEBU_Ctypevec@@@Z", "_Towlower");
		addEquivSymbols("_wcsncpy_s_downlevel", "_wcsncpy_s");
		addEquivSymbols("_strnlen_downlevel", "_strnlen");
		addEquivSymbols("GetProxyDllInfo","_GetProxyDllInfo@8");
		addEquivSymbols("DllGetClassObject","_DllGetClassObject@12");
		addEquivSymbols("_PrxDllGetClassObject@12", "_DllGetClassObject@12");
		addEquivSymbols("__itoa_s_downlevel", "__itow_s");
		addEquivSymbols("?StringCbVPrintfA@@YGJPADIPBD0@Z", "?StringCchVPrintfW@@YGJPAGIPBGPAD@Z");
		addEquivSymbols("?UShortMult@@YGJGGPAG@Z", "?RtlUShortMult@@YGJGGPAG@Z");
		addEquivSymbols("??1?$CStringT@GV?$StrTraitATL@GV?$ChTraitsCRT@G@ATL@@@ATL@@@ATL@@QAE@XZ",
						"??1?$CStringT@_WV?$StrTraitMFC@_WV?$ChTraitsOS@_W@ATL@@@@@ATL@@QAE@XZ");
		addEquivSymbols("?memcpy_s@Checked@ATL@@YAXPAXIPBXI@Z", "?memmove_s@Checked@ATL@@YAXPAXIPBXI@Z");
		addEquivSymbols("?tcsncpy_s@Checked@ATL@@YAHPAGIPBGI@Z", "?memmove_s@Checked@ATL@@YAXPAXIPBXI@Z");
		addEquivSymbols("?wmemcpy_s@Checked@ATL@@YAXPAGIPBGI@Z", "?memmove_s@Checked@ATL@@YAXPAXIPBXI@Z");
		addEquivSymbols("??$AtlMultiply@I@ATL@@YAJPAIII@Z","??$AtlMultiply@K@ATL@@YAJPAKKK@Z");
		addEquivSymbols("__it_wcsncpy", "_wcsncpy");
		addEquivSymbols("??1?$CFixedStringT@V?$CStringT@GV?$StrTraitATL@GV?$ChTraitsCRT@G@ATL@@@ATL@@@ATL@@$0BA@@ATL@@UAE@XZ",
						"??1?$CFixedStringT@V?$CStringT@DV?$StrTraitMFC@DV?$ChTraitsCRT@D@ATL@@@@@ATL@@$0EA@@ATL@@UAE@XZ");
		addEquivSymbols("?StringCbCatA@@YGJPADIPBD@Z", "_StringCchCatA@12");
		addEquivSymbols("??0?$CStringT@GV?$StrTraitATL@GV?$ChTraitsCRT@G@ATL@@@ATL@@@ATL@@QAE@PBG@Z",
						"??0?$CStringT@DV?$StrTraitMFC@DV?$ChTraitsCRT@D@ATL@@@@@ATL@@QAE@PB_W@Z");
		addEquivSymbols("UShortAdd", "RtlUShortAdd");
		addEquivSymbols("_StringCchPrintfA", "?StringCbPrintfA@@YAJPADIPBDZZ");
		addEquivSymbols("?StringCbCopyA@@YGJPADIPBD@Z", "_StringCchCopyA@12");

		// 64-bit
		addEquivSymbols("??1?$CTempBuffer@G$0BAA@VCCRTAllocator@ATL@@@ATL@@QEAA@XZ","??1?$CTempBuffer@D$0IA@VCCRTAllocator@ATL@@@ATL@@QEAA@XZ");
		addEquivSymbols("?IsEqualGUID@@YAHAEBU_GUID@@0@Z","IsEqualGUID");
		addEquivSymbols("??1?$CAtlSafeAllocBufferManager@V_CCRTAllocator@_ATL_SAFE_ALLOCA_IMPL@ATL@@@_ATL_SAFE_ALLOCA_IMPL@ATL@@QEAA@XZ",
						"??1?$CAtlSafeAllocBufferManager@VCCRTAllocator@ATL@@@_ATL_SAFE_ALLOCA_IMPL@ATL@@QEAA@XZ");
		addEquivSymbols("??_E_Locimp@locale@std@@MEAAPEAXI@Z","??_G_Locimp@locale@std@@MEAAPEAXI@Z");
		addEquivSymbols("?StringCchCopyW@@YAJPEAG_KPEBG@Z","StringCchCopyW");
		addEquivSymbols("StringCchPrintfA","?StringCbPrintfA@@YAJPEAD_KPEBDZZ");
		addEquivSymbols("?StringCchCatA@@YAJPEAD_KPEBD@Z","StringCchCatA");
		addEquivSymbols("?StringCbCatA@@YAJPEAD_KPEBD@Z","StringCchCatA");
		addEquivSymbols("entry","mainCRTStartup");
		addEquivSymbols("entry","wmainCRTStartup");
		addEquivSymbols("entry","WinMainCRTStartup");
		addEquivSymbols("WPP_SF_ii","WPP_SF_qq");
		addEquivSymbols("WPP_SF_DDDDD","WPP_SF_ddddd");
		addEquivSymbols("?FDIDestroy@@$$J0YAHPEAX@Z","FDIDestroy");
		addEquivSymbols("??1?$CTempBuffer@G$0IA@VCCRTAllocator@ATL@@@ATL@@QEAA@XZ","??1?$CTempBuffer@D$0IA@VCCRTAllocator@ATL@@@ATL@@QEAA@XZ");
		addEquivSymbols("WPP_SF_xx","WPP_SF_qq");
		addEquivSymbols("WPP_SF_iii","WPP_SF_qqq");
		addEquivSymbols("RtlStringCchCopyW","StringCchCopyW");
		addEquivSymbols("_strcmpi","_stricmp");
		addEquivSymbols("WPP_SF_DDDDDDDD","WPP_SF_dddddddd");
		addEquivSymbols("?StringCchPrintfA@@YAJPEAD_KPEBDZZ","?StringCbPrintfA@@YAJPEAD_KPEBDZZ");
		addEquivSymbols("WPP_SF_h","WPP_SF_H");
		addEquivSymbols("WPP_SF_qqDD","WPP_SF_qqdd");
		addEquivSymbols("WPP_SF_DqD","WPP_SF_dqd");
		addEquivSymbols("WPP_SF_Dq","WPP_SF_dq");
	}

	private void findDomainFiles(LinkedList<DomainFile> programs, DomainFolder folder)
			throws VersionException, CancelledException, IOException {
		DomainFile[] files = folder.getFiles();
		for (DomainFile domainFile : files) {
			monitor.checkCanceled();
			if (domainFile.getContentType().equals(ProgramContentHandler.PROGRAM_CONTENT_TYPE)) {
				programs.add(domainFile);
			}
		}
		DomainFolder[] folders = folder.getFolders();
		for (DomainFolder domainFolder : folders) {
			monitor.checkCanceled();
			findDomainFiles(programs, domainFolder);
		}
	}

	private boolean checkNames(String a,String b) {
		if (a.equals(b))
			return true;
		return equivSymbols.contains(new SymbolPair(a,b));
	}

	private void processFunctionResult(FidSearchResult result)
			throws CancelledException, IOException {
		StatRecord record = statRecord;
		record.totalFunction += 1;
		if (result.matches==null || result.matches.size() == 0) {
			record.noMatch += 1;
		}
		else {
			Program program = result.function.getProgram();
			matchAnalysis.analyzeNames(result.matches, program, monitor);
			String finalMatchName = null;
			boolean matchHappened = false;
			if (matchAnalysis.getMostOptimisticCount() > 1) {
				if (matchAnalysis.getOverallScore() >= FidService.MULTINAME_SCORE_THRESHOLD) {
					record.matchMultiply += 1;
					matchHappened = true;		// FID will put down a multiple match label
				}
			}
			else {
				record.matchUniquely += 1;
				matchHappened = true;			// FID will put down a single match
				finalMatchName = matchAnalysis.getNameIterator().next();
			}
			NameVersions nameVersions = NameVersions.generate(result.function.getName(), program);
			String strippedTemplateName = null;
			if (nameVersions.demangledBaseName != null) {
				strippedTemplateName =
					MatchNameAnalysis.removeTemplateParams(nameVersions.demangledBaseName);
			}
			boolean exactNameMatch = false;
			Iterator<String> iter = matchAnalysis.getRawNameIterator();
			while(iter.hasNext()) {
				String raw = iter.next();
				NameVersions matchNames = NameVersions.generate(raw, program);
				if (matchNames.rawName == null) continue;
				if (checkNames(nameVersions.rawName,matchNames.rawName)) {
					exactNameMatch = true;
					break;
				}
				if (checkNames(nameVersions.similarName,matchNames.similarName)) {
					exactNameMatch = true;
					break;
				}
				if (nameVersions.demangledBaseName == null) continue;
				if (matchNames.demangledBaseName == null) continue;
				if (checkNames(nameVersions.demangledBaseName,matchNames.demangledBaseName)) {
					exactNameMatch = true;
					break;
				}
				if (matchNames.demangledBaseName != null && strippedTemplateName != null) {
					String strippedName =
						MatchNameAnalysis.removeTemplateParams(matchNames.demangledBaseName);
					if (strippedName != null) {
						if (strippedName.equals(strippedTemplateName)) {
							exactNameMatch = true;
							break;
						}
					}
				}
			}
			if (exactNameMatch)
				record.nameMatched += 1;

			float score = result.matches.get(0).getOverallScore();
			if (exactNameMatch && ((score < scoreThreshold) || !matchHappened)) {
				MatchRecord matchRecord = new MatchRecord(result,null,false);
				StringBuilder buffer = new StringBuilder();
				matchRecord.print(buffer);
				lowTruePositive.append(buffer.toString());
				lowTruePositive.append('\n');
			}
			else if ((!exactNameMatch) && (score >= scoreThreshold) && matchHappened) {
				record.falsePositive += 1;
				MatchRecord matchRecord = new MatchRecord(result,finalMatchName,true);
				StringBuilder buffer = new StringBuilder();
				matchRecord.print(buffer);
				highFalsePositive.append(buffer.toString());
				highFalsePositive.append('\n');
			}
		}
		
	}

	private void processProgram(Program program,FidQueryService queryService) throws MemoryAccessException, CancelledException, VersionException, IOException {
		FidProgramSeeker programSeeker = service.getProgramSeeker(program,queryService, 10.0f);
		FunctionIterator iter = program.getFunctionManager().getFunctionsNoStubs(true);
		while(iter.hasNext()) {
			Function func = iter.next();
			if (func.getName().startsWith("FUN_") || func.getName().startsWith("Ordinal_"))
				continue;
			FidSearchResult searchResult = programSeeker.searchFunction(func, monitor);
			if (searchResult == null) continue;		// Could not hash function
			processFunctionResult(searchResult);
		}
	}

	private LinkedList<DomainFile> buildDomainFileList() throws CancelledException, VersionException, IOException {
		ArrayList<DomainFolder> folders = new ArrayList<DomainFolder>();
		while (true) {
			monitor.checkCanceled();
			try {
				DomainFolder folder =
					askProjectFolder("Add a top-level project folder (cancel to quit)");
				folders.add(folder);
			}
			catch (CancelledException e) {
				break;
			}
		}

		LinkedList<DomainFile> domainFiles = new LinkedList<DomainFile>();
		monitor.setMessage("Finding domain files...");
		for (DomainFolder folder : folders) {
			monitor.checkCanceled();
			findDomainFiles(domainFiles, folder);
		}
		return domainFiles;
	}

	@Override
	protected void run() throws Exception {
		initialize();
		
		LinkedList<DomainFile> programList = buildDomainFileList();
		File lowFile = askFile("Select file to report true matches", "OK");
		File highFile = askFile("Select file to report false positives", "OK");
		scoreThreshold = (float)askDouble("Choose score threshold", "OK");
		
		lowTruePositive = new FileWriter(lowFile);
		highFalsePositive = new FileWriter(highFile);

		FidQueryService queryService = null;
		Language lastLanguage = null;
		int maxPrograms = programList.size();
		int counter = 0;
		try {
			for(DomainFile domainFile : programList) {
				Program program = null;
				try {
					program = (Program) domainFile.getDomainObject(this, false, false, monitor);
					if (queryService == null || !lastLanguage.equals(program.getLanguage())) {
						if (queryService != null)
							queryService.close();
						lastLanguage = program.getLanguage();
						queryService = service.openFidQueryService(lastLanguage, false);
					}
					processProgram(program,queryService);
					counter += 1;
					monitor.setMessage("Processing programs ...");
					monitor.initialize(maxPrograms);
					monitor.setProgress(counter);
				}
				finally {
					if (program != null)
						program.release(this);
				}
			}
		} catch(CancelledException ex) {
			// A cancel in middle of processing still allows results to get printed
		}

		queryService.close();
		lowTruePositive.close();
		highFalsePositive.close();
	
		println(StatRecord.getColumns());
		StringBuilder buffer = new StringBuilder();
		statRecord.print(buffer);
		println(buffer.toString());
	}

}
