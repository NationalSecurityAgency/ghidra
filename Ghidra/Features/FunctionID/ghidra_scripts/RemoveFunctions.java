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
import java.io.IOException;
import java.util.*;

import generic.stl.Pair;
import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.db.*;

/**
 * Example script for bulk removal of functions from a FID database.  Hashes can be added to the list
 * in buildKnownHashes() manually or by running another script that generates hashes
 * (like IdentifyPotentialWrapperFunctions) and copying the results in here.  Running this script
 * marks any function matching one of these hashes as unmatchable (auto-fail).
 */
public class RemoveFunctions extends GhidraScript {
	private LinkedList<Pair<Short, Long>> REMOVE_HASHES = new LinkedList<>();
	private LinkedList<Pair<Short, Long>> FORCE_SPECIFIC = new LinkedList<>();
	private LinkedList<Pair<Short, Long>> FORCE_RELATION = new LinkedList<>();
	private LinkedList<Pair<Short, Long>> AUTO_PASS = new LinkedList<>();
	private LinkedList<String> AUTO_FAIL_REGEX = new LinkedList<>();
	private LinkedList<Pair<String, Pair<Long, Long>>> SPECIAL_PARENT = new LinkedList<>();

	/**
	 * FID hash adjustments built for 32-bit Visual Studio libraries
	 */
	private void buildKnownHashes32() {
		FORCE_RELATION.add(fh(12, 0xc6895bb538b9efedL));	// ??1CMFCToolBarButtonsListButton@@UAE@XZ
		FORCE_RELATION.add(fh(9, 0xf79b0bad7e386093L));		// ??1CSmartDockingManager@@UAE@XZ
		FORCE_RELATION.add(fh(9, 0xee02fc471f1fe023L));		// ??1CAccessibleProxy@ATL@@UAE@XZ
		FORCE_RELATION.add(fh(13, 0xfc1069edfcb68a86L));	// ??0PAGE_INFO@CPreviewView@@QAE@XZ
		FORCE_RELATION.add(fh(14, 0xd02b51fb54e99a6L));		// ??4XID@CMFCRibbonInfo@@QAEAAV01@ABV01@@Z
		FORCE_RELATION.add(fh(24, 0xfbc5755fc4b3088dL));	// ?ReleaseDirectDraw@CLoadDirectDraw@@QAEXXZ
		FORCE_RELATION.add(fh(16, 0xf2fafe04b5c16767L));	// ?Restart@CBaseReferenceClock@@IAEX_J@Z
		FORCE_RELATION.add(fh(15, 0x40f4e3dea772381aL));	// ?GetClassID@CPropertySet@@QAE?AU_GUID@@XZ
		FORCE_RELATION.add(fh(16, 0xdbaf217b6864fef7L));	// ?GetValue@CMFCMaskedEdit@@IBE?BV?$CStringT@DV?$StrTraitMFC@DV?$ChTraitsCRT@D@ATL@@@@@ATL@@XZ
		FORCE_RELATION.add(fh(21, 0xd58e87fa78cc0557L));	// ?QueryInterface@CBaseBasicVideo@@UAGJABU_GUID@@PAPAX@Z
		FORCE_RELATION.add(fh(13, 0x7198eafea73405ccL));	// ??_G?$CList@IAAI@@UAEPAXI@Z
		FORCE_RELATION.add(fh(25, 0xf965f87e1a7a2d4dL));	// ?AtlComPtrAssign@ATL@@YGPAUIUnknown@@PAPAU2@PAU2@@Z
		FORCE_RELATION.add(fh(12, 0x423483b370f203a9L));	// ??A?$CSimpleStringT@_W$0A@@ATL@@QBE_WH@Z
		FORCE_RELATION.add(fh(14, 0x1300b11d1740771L));		// ??0_Push_finalizer@_Micro_queue@details@Concurrency@@QAE@AAU123@I@Z
		FORCE_RELATION.add(fh(13, 0x54044bc079343f1dL));	// ??0_Generic_error_category@std@@QAE@XZ
		FORCE_RELATION.add(fh(11, 0x7fd89305977ee8c2L));	// ??0CMFCToolBarInfo@@QAE@XZ
		FORCE_RELATION.add(fh(11, 0x524d06c7c0970aedL));	// ??_GAFX_MODULE_STATE@@UAEPAXI@Z
		FORCE_RELATION.add(fh(25, 0x3f879fafaef651aaL));	// __get_amblksiz
		FORCE_RELATION.add(fh(15, 0x694404f614abe0b5L));	// ??_GCArchiveException@@UAEPAXI@Z
		FORCE_RELATION.add(fh(14, 0xb92627d7f5c53d94L));	// _WPP_SF_x@24
		FORCE_RELATION.add(fh(12, 0x73b455b7f2deffe9L));	// ?Lock@CAggDrawSurface@@UAGJPAUtagRECT@@PAU_DDSURFACEDESC@@KPAX@Z
		FORCE_RELATION.add(fh(18, 0x360705da55b5b1e0L));	// ?__CreateTimerQueueTimer@platform@details@Concurrency@@YAHPAPAXPAXP6GX1E@Z1KKK@Z
		FORCE_RELATION.add(fh(20, 0x8b1bd24c9ecc8249L));	// ??0CPrintPreviewState@@QAE@XZ
		FORCE_RELATION.add(fh(15, 0xb7c94f9f51b07e8bL));	// _DnssrvMidlAllocZero@4
		FORCE_RELATION.add(fh(11, 0x3be9fdaad7ec119cL));	// ??0RealizedChore@details@Concurrency@@QAE@P6AXPAX@Z0@Z
		FORCE_RELATION.add(fh(12, 0xa7d4de5353635ac0L));	// ?GetStartPosition@CRichEditDoc@@UBEPAU__POSITION@@XZ
		FORCE_RELATION.add(fh(11, 0x8566fc3e26094da8L));	// ?EnumOverlayZOrders@CAggDrawSurface@@UAGJKPAXP6GJPAUIDirectDrawSurface@@PAU_DDSURFACEDESC@@0@Z@Z
		FORCE_RELATION.add(fh(15, 0x1641da2efe9de56dL));	// ??1CAnimationRect@@UAE@XZ
		FORCE_RELATION.add(fh(32, 0x471007243caa0c09L));	// ??1CDaoRecordView@@UAE@XZ
		FORCE_RELATION.add(fh(9, 0xf7707ce88b335cc0L));		// ??1CFileFind@@UAE@XZ
		FORCE_RELATION.add(fh(11, 0x2aed7618d13c9213L));	// ??$?6DV?$StrTraitMFC@DV?$ChTraitsCRT@D@ATL@@@@@CDumpContext@@QAEAAV0@ABV?$CStringT@DV?$StrTraitMFC@DV?$ChTraitsCRT@D@ATL@@@@@ATL@@@Z
		FORCE_RELATION.add(fh(11, 0x39409061f0b49a24L));	// ??0_AfxUINT128@@QAE@_K@Z
		FORCE_RELATION.add(fh(12, 0x65c7fcb8d51a2b30L));	// ??_G?$TItem@UAPOHandle@@@@QAEPAXI@Z
		FORCE_RELATION.add(fh(10, 0xfe4ba097e732c546L));	// ??1XElementButtonApplication@CMFCRibbonInfo@@UAE@XZ
		FORCE_RELATION.add(fh(35, 0xd31a59bc8af60e1dL));	// ??1CMFCEditBrowseCtrl@@UAE@XZ
		FORCE_RELATION.add(fh(11, 0xab3d076b2dc6c4daL));	// ??1CMFCVisualManagerBitmapCache@@UAE@XZ
		FORCE_RELATION.add(fh(38, 0x261a7bf7c2d0bea9L));	// ??1CMFCDesktopAlertWnd@@UAE@XZ
		FORCE_RELATION.add(fh(17, 0x69b356515597693eL));	// ??0XQATItem@XQAT@CMFCRibbonInfo@@QAE@ABV012@@Z
		FORCE_RELATION.add(fh(13, 0x1b3508ee4f62d1a0L));	// ??_GBitmap@Gdiplus@@UAEPAXI@Z
		FORCE_RELATION.add(fh(5, 0xb35317b538e7fa8cL));		// ??1CBaseVideoRenderer@@UAE@XZ
		FORCE_RELATION.add(fh(13, 0xd042ce91efb0c886L));	// ?BltFast@CAggDrawSurface@@UAGJKKPAUIDirectDrawSurface@@PAUtagRECT@@K@Z
		FORCE_RELATION.add(fh(9, 0xf8434e36a53623aL));		// ??1CParkingWnd@@UAE@XZ
		FORCE_RELATION.add(fh(13, 0xaa62e68c558e1314L));	// ??0CMFCToolBarDateTimeCtrlImpl@@QAE@XZ
		FORCE_RELATION.add(fh(15, 0xd9842cc1d6a8c16eL));	// ??0?$CRowset@VCAccessorBase@ATL@@@ATL@@QAE@PAUIRowset@@@Z
		FORCE_RELATION.add(fh(10, 0xb69b382c183aa9d2L));	// ??1CRecentDockSiteInfo@@UAE@XZ
		FORCE_RELATION.add(fh(18, 0xda54e37f47ee0cdfL));	// ??1CLongBinary@@UAE@XZ
		FORCE_RELATION.add(fh(19, 0x7ae06abcc70f8143L));	// ?SetSite@CPrintDialogEx@@UAGJPAUIUnknown@@@Z
		FORCE_RELATION.add(fh(9, 0xc96e57c3466d7a27L));		// ??1?$ISource@I@Concurrency@@UAE@XZ
		FORCE_RELATION.add(fh(9, 0x6943a1ade913a86L));		// ??1_variant_t@@QAE@XZ
		FORCE_RELATION.add(fh(14, 0x6c22232059921accL));	// ??1CMFCOutlookBarPane@@UAE@XZ
		FORCE_RELATION.add(fh(15, 0x893104c308ed3ce2L));	// ?GetPixelFormat@Image@Gdiplus@@QAEHXZ
		FORCE_RELATION.add(fh(13, 0x4efc77b22a40668cL));	// ??_Gbad_alloc@std@@UAEPAXI@Z
		FORCE_RELATION.add(fh(21, 0x5f47f93ed7f13499L));	// ?widen@?$ctype@G@std@@QBEGD@Z
		FORCE_RELATION.add(fh(11, 0x6d042e51a9dcabbaL));	// ??I?$_CIP@UIBindCtx@@$1?IID_IBindCtx@@3U_GUID@@B@@QAEPAPAUIBindCtx@@XZ
		FORCE_RELATION.add(fh(6, 0x4b0ff9672fe08626L));		// ??1ScheduleGroupBase@details@Concurrency@@UAE@XZ
		FORCE_RELATION.add(fh(12, 0xde6d4d6d0fb3599dL));	// ?InternalSetAtIndex@?$CSimpleArray@KV?$CSimpleArrayEqualHelper@K@ATL@@@ATL@@QAEXHABK@Z
		FORCE_RELATION.add(fh(13, 0xca2f9cad505f5c50L));	// ??_G?$ISource@I@Concurrency@@UAEPAXI@Z
		FORCE_RELATION.add(fh(7, 0x21f960f6f55ff791L));		// ??1?$CXMLNode@UIXMLDOMDocument@@@ATL@@UAE@XZ
		FORCE_RELATION.add(fh(8, 0xf3faa55d0902802L));		// ??1CManualAccessor@ATL@@QAE@XZ
		FORCE_RELATION.add(fh(14, 0x3b286952ce952857L));	// ?AfxOleRegisterServerClass@@YGHABU_GUID@@PBD11W4OLE_APPTYPE@@PAPBD3H1@Z
		FORCE_RELATION.add(fh(4, 0x530c3899dba0cc9dL));		// ??1CBaseList@@QAE@XZ
		FORCE_RELATION.add(fh(15, 0xd19e3babd20b0b5bL));	// ??0CWnd@@QAE@XZ
		FORCE_RELATION.add(fh(9, 0x6d2be8e93610ff51L));		// ??$_As@VSchedulingNode@details@Concurrency@@@location@Concurrency@@QBEPAVSchedulingNode@details@1@XZ
		FORCE_RELATION.add(fh(11, 0x1dc5b781f7b5a6e6L));	// ??0<lambda0>@?A0x8894c2c9@Concurrency@@QAE@ACIAAIAAV?$single_assignment@I@2@@Z
		FORCE_RELATION.add(fh(13, 0x6afdaf056a3b372cL));	// ??_G?$basic_istream@DU?$char_traits@D@std@@@std@@UAEPAXI@Z
		FORCE_RELATION.add(fh(19, 0x95c64fdd68dd78d2L));	// ??0?$CArray@HABH@@QAE@XZ
		FORCE_RELATION.add(fh(14, 0xd8df9b07e154fdbfL));	// ??1CRichEditCntrItem@@UAE@XZ
		FORCE_RELATION.add(fh(11, 0x3c9fecb05343dec4L));	// ?GetTypeInfoCount@CBaseDispatch@@QAGJPAI@Z
		FORCE_RELATION.add(fh(10, 0xb7661a8d952a3c36L));	// _Dns_ReverseNameToAddress_A@16
		FORCE_RELATION.add(fh(26, 0x7b6a6376507e6ed1L));	// ??1XElementButtonApplication@CMFCRibbonInfo@@UAE@XZ
		FORCE_RELATION.add(fh(11, 0x529f71350713eff0L));	// _DnsPrint_RawOctets@24
		FORCE_RELATION.add(fh(15, 0xc4ac7d943cff7be5L));	// ??0COleDialog@@QAE@PAVCWnd@@@Z
		FORCE_RELATION.add(fh(10, 0x40fa05ee45f340f9L));	// ??0?$CTypedPtrList@VCPtrList@@PAUCOleControlSiteOrWnd@@@@QAE@H@Z
		FORCE_RELATION.add(fh(10, 0x6cb0ccfc7a7b65c7L));	// ?SetCheckedImage@CMFCButton@@QAEXPAUHBITMAP__@@H0H0@Z
		FORCE_RELATION.add(fh(29, 0x584922509ca6f2fdL));	// ??1CMFCPopupMenuBar@@UAE@XZ
		FORCE_RELATION.add(fh(12, 0x2e7a23324afbe34eL));	// ??1CCommandLineInfo@@UAE@XZ
		FORCE_RELATION.add(fh(25, 0x15f39174075dff3eL));	// ??0?$CComPtr@UIMoniker@@@ATL@@QAE@PAUIMoniker@@@Z
		FORCE_RELATION.add(fh(15, 0xed52233b5c5d179aL));	// ?GetTypeInfo@?$IAccessibleProxyImpl@VCAccessibleProxy@ATL@@@ATL@@UAGJIKPAPAUITypeInfo@@@Z
		FORCE_RELATION.add(fh(16, 0x3d5d986932f74e2bL));	// ??4XQATItem@XQAT@CMFCRibbonInfo@@QAEAAV012@ABV012@@Z
		FORCE_RELATION.add(fh(15, 0xb36aed13bafd4128L));	// ??A?$CSimpleArray@KV?$CSimpleArrayEqualHelper@K@ATL@@@ATL@@QAEAAKH@Z
		FORCE_RELATION.add(fh(27, 0x38ba8218a1574c02L));	// ?SetClassID@CPropertySet@@QAEXU_GUID@@@Z
		FORCE_RELATION.add(fh(10, 0xd2d3085f0326439dL));	// ?GetElements@CMFCRibbonBaseElement@@UAEXAAV?$CArray@PAVCMFCRibbonBaseElement@@PAV1@@@@Z
		FORCE_RELATION.add(fh(18, 0x315abdf2c4531012L));	// ??0AFX_DDPDATA@@QAE@PAXHH0IPBD@Z
		FORCE_RELATION.add(fh(15, 0x50bd29d951c096feL));	// ??0?$CXMLNode@UIXMLDOMNode@@@ATL@@QAE@PAUIXMLDOMNode@@@Z
		FORCE_RELATION.add(fh(17, 0x1a2495664f6d92c3L));	// ??0system_error@std@@QAE@ABV01@@Z
		FORCE_RELATION.add(fh(25, 0x17f377f4c4798c42L));	// ??0?$_Async_send_queue@V?$message@I@Concurrency@@@details@Concurrency@@QAE@XZ
		FORCE_RELATION.add(fh(10, 0xe8eb87761b5542b7L));	// ?Create@CDockSite@@UAEHKABUtagRECT@@PAVCWnd@@KPAUCCreateContext@@@Z
		FORCE_RELATION.add(fh(12, 0x51468e5f80832c5eL));	// ?RemoveAll@?$CSimpleArray@GV?$CSimpleArrayEqualHelper@G@ATL@@@ATL@@QAEXXZ
		FORCE_RELATION.add(fh(9, 0xfe495b1bffb47f85L));		// ??_G?$CRowset@VCAccessorBase@ATL@@@ATL@@QAEPAXI@Z
		FORCE_RELATION.add(fh(12, 0x20ecf51225885a5aL));	// _R_DnssrvOperation2@36
		FORCE_RELATION.add(fh(7, 0x11dc2824d0edcc80L));		// ??0CDC@@QAE@XZ
		FORCE_RELATION.add(fh(14, 0xa076d9f8486f4667L));	// ?SetSubtype@CMediaType@@QAEXPBU_GUID@@@Z
		FORCE_RELATION.add(fh(12, 0x4f3264427c9d684fL));	// ?AfxInvariantStrICmp@@YAHPBD0@Z
		FORCE_RELATION.add(fh(16, 0x3db72b66fe66eccbL));	// ??0Graphics@Gdiplus@@QAE@PAUHDC__@@@Z
		FORCE_RELATION.add(fh(10, 0x42b584c04453465eL));	// ?Create@CImage@ATL@@QAEHHHHK@Z
		FORCE_RELATION.add(fh(7, 0xa0e6d60f12731076L));		// ??1?$CComObject@VCPTEventSink@@@ATL@@QAE@XZ
		FORCE_RELATION.add(fh(9, 0x54228b0585854bfdL));		// ?GetPaneCount@CMultiPaneFrameWnd@@UBEHXZ
		FORCE_RELATION.add(fh(3, 0x70aacabe8adeb504L));		// ??1CVideoTransformFilter@@UAE@XZ
		FORCE_RELATION.add(fh(12, 0xfb1ea7c531542e48L));	// ??_G?$CArray@HABH@@UAEPAXI@Z
		FORCE_RELATION.add(fh(13, 0xad7f29dd6f059476L));	// ??0?$CTypedPtrList@V?$CList@PAXPAX@@PAUCOleControlSiteOrWnd@@@@QAE@H@Z
		FORCE_RELATION.add(fh(11, 0xe5b805cebfd5127L));		// ?_Getname@_Locinfo@std@@QBE?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@V_STL70@@@2@XZ
		FORCE_RELATION.add(fh(15, 0x4e0920960b48ae7eL));	// _TraceError@8
		FORCE_RELATION.add(fh(12, 0x60d88814d47b29b9L));	// ?InvokeHelper@COleDispatchDriver@@QAAXJGGPAXPBEZZ
		FORCE_RELATION.add(fh(13, 0x3f724d88e27bd1d1L));	// ?DDX_FieldText@@YGXPAVCDataExchange@@HAAEPAVCDaoRecordset@@@Z
		FORCE_RELATION.add(fh(15, 0x99e14403171f2be9L));	// ?RtlULongToUShort@@YGJKPAG@Z
		FORCE_RELATION.add(fh(15, 0x3cd4904368bf315cL)); 	// ??_G?$_MallocaArrayHolder@PAVContext@Concurrency@@@details@Concurrency@@UAEPAXI@Z
		FORCE_RELATION.add(fh(4, 0xb8db1dacc3441a8fL));		// ??1_Timer@details@Concurrency@@MAE@XZ
		FORCE_RELATION.add(fh(14, 0x7b2255d33cddad65L));	// ??_GThreadInternalContext@details@Concurrency@@UAEPAXI@Z

		REMOVE_HASHES.add(fh(4, 0x8f0554c0936e0e0dL));		// ?AddPaneToList@CPaneContainerManager@@QAEXPAVCDockablePane@@@Z
		REMOVE_HASHES.add(fh(17, 0x6875ba2bfa94ae88L));		// ??1?$CComPtrBase@UIAccessibleProxy@@@ATL@@QAE@XZ
		REMOVE_HASHES.add(fh(29, 0x4db81591ee928ce3L));		// ??1CMFCVisualManagerBitmapCache@@UAE@XZ
		REMOVE_HASHES.add(fh(10, 0xf7b4ade6aff8fb76L));		// ??0?$CAtlSafeAllocBufferManager@VCCRTAllocator@ATL@@@_ATL_SAFE_ALLOCA_IMPL@ATL@@QAE@XZ
		REMOVE_HASHES.add(fh(9, 0x8e0da9ecbc5799f6L));		// ??0?$CComHeapPtr@UtagDBPROPSET@@@ATL@@QAE@XZ
		REMOVE_HASHES.add(fh(11, 0x3cb2b59f05ef26daL));		//??$?0P6A_NABW4agent_status@Concurrency@@@Z@?$function@$$A6A_NABW4agent_status@Concurrency@@@Z@tr1@std@@QAE@P6A_NABW4agent_status@Concurrency@@@Z@Z
		REMOVE_HASHES.add(fh(14, 0xd66b8a76c7a5283aL));		// ??_G?$CArray@HABH@@UAEPAXI@Z
		REMOVE_HASHES.add(fh(26, 0x62b27011e0b64869L));		// ??1COleResizeBar@@UAE@XZ
		REMOVE_HASHES.add(fh(10, 0xeeb578e8c50baaebL));		// ??1?$ThreadProxyFactory@VFreeThreadProxy@details@Concurrency@@@details@Concurrency@@UAE@XZ
		REMOVE_HASHES.add(fh(15, 0x550b5d5ca0b00c01L));		// ??_G?$CArray@HABH@@UAEPAXI@Z
		REMOVE_HASHES.add(fh(7, 0x84d01243dfb8b9cbL));		// ??1?$_DebugMallocator@H@@QAE@XZ
		REMOVE_HASHES.add(fh(8, 0x3d7242fc6eb079a7L));		// ??1<lambda_61f7764e5b8087545c74b0c2f4f68b12>@@QAE@XZ
		REMOVE_HASHES.add(fh(7, 0x690dec263cb912aaL));		// ?OnDrawTasksGroupAreaBorder@CMFCVisualManagerOfficeXP@@MAEXPAVCDC@@VCRect@@HH@Z
		REMOVE_HASHES.add(fh(7, 0x6b745608ae7e77fbL));		// ??1?$CArray@...  destructors based on CArray

		FORCE_SPECIFIC.add(fh(2, 0x5ef2f47ee7151243L));		// __SEH_epilog4_GS, __EH_epilog3_GS, and __EH_epilog3_catch_GS
		FORCE_RELATION.add(fh(2, 0x5ef2f47ee7151243L));
		AUTO_PASS.add(fh(2, 0x5ef2f47ee7151243L));

		FORCE_SPECIFIC.add(fh(2, 0x96a4a6fd5694523bL));		// __SEH_epilog4_GS, __EH_epilog3_GS, and __EH_epilog3_catch_GS
		FORCE_RELATION.add(fh(2, 0x96a4a6fd5694523bL));
		AUTO_PASS.add(fh(2, 0x96a4a6fd5694523bL));

		FORCE_SPECIFIC.add(fh(3, 0xf1feea7baf6e82d5L));		// ___crtExitProcess
		FORCE_RELATION.add(fh(3, 0xf1feea7baf6e82d5L));
		AUTO_PASS.add(fh(3, 0xf1feea7baf6e82d5L));

		FORCE_SPECIFIC.add(fh(11, 0x78a6fb00a4960a21L));	// __EH_epilog3
		AUTO_PASS.add(fh(11, 0x78a6fb00a4960a21L));
		FORCE_SPECIFIC.add(fh(12, 0x48eae52e9a6f402cL));	// __EH_epilog3_align
		AUTO_PASS.add(fh(12, 0x48eae52e9a6f402cL));
		FORCE_SPECIFIC.add(fh(12, 0x69887e7bad43a8a3L));	// _wcsnlen
		AUTO_PASS.add(fh(12, 0x69887e7bad43a8a3L));
		FORCE_SPECIFIC.add(fh(12, 0x56305d306ade4984L));	// __EH_epilog3_align
		AUTO_PASS.add(fh(12, 0x56305d306ade4984L));
		FORCE_SPECIFIC.add(fh(10, 0xc04d213e1a231d0fL));	// __abnormal_termination
		AUTO_PASS.add(fh(10, 0xc04d213e1a231d0fL));
		FORCE_SPECIFIC.add(fh(11, 0x1af0a46bb2b2655bL));	// __SEH_epilog4
		AUTO_PASS.add(fh(11, 0x1af0a46bb2b2655bL));
		FORCE_SPECIFIC.add(fh(10, 0x362f7d880d9de4aeL));	// __frnd
		AUTO_PASS.add(fh(10, 0x362f7d880d9de4aeL));
		FORCE_SPECIFIC.add(fh(9, 0xc9f2110bfb24660fL));		// __SEH_epilog
		AUTO_PASS.add(fh(9, 0xc9f2110bfb24660fL));
		FORCE_SPECIFIC.add(fh(9, 0x157890c52d4d7519L));		// __SEH_epilog
		AUTO_PASS.add(fh(9, 0x157890c52d4d7519L));
		FORCE_SPECIFIC.add(fh(8, 0xa11e5331b6086ac4L));		// _rand
		AUTO_PASS.add(fh(8, 0xa11e5331b6086ac4L));
		FORCE_SPECIFIC.add(fh(12, 0xfdbb6823ea5e6eaeL));	// _wcslen
		AUTO_PASS.add(fh(12, 0xfdbb6823ea5e6eaeL));
		FORCE_SPECIFIC.add(fh(9, 0xe1e948c7479ce80L));		// ?Init@CComCriticalSection@ATL@@QAEJXZ
		AUTO_PASS.add(fh(9, 0xe1e948c7479ce80L));

		// Distinguishing _memcpy from _memmove
		SPECIAL_PARENT.add(new Pair<String, Pair<Long, Long>>("_memcpy",
			new Pair<Long, Long>(0x33d1cb7adc1726dbL, 0x81300cda8b24004bL)));
		SPECIAL_PARENT.add(new Pair<String, Pair<Long, Long>>("_memcpy",
			new Pair<Long, Long>(0x33d1cb7adc1726dbL, 0xe70c71e845db7694L)));
		SPECIAL_PARENT.add(new Pair<String, Pair<Long, Long>>("_memcpy",
			new Pair<Long, Long>(0xcf7c351b23b36e10L, 0xd835fe2e6794b2d0L)));
		SPECIAL_PARENT.add(new Pair<String, Pair<Long, Long>>("_memcpy",
			new Pair<Long, Long>(0xcf7c351b23b36e10L, 0x8176bdc9ca178984L)));
		SPECIAL_PARENT.add(new Pair<String, Pair<Long, Long>>("_memcpy",
			new Pair<Long, Long>(0xcf7c351b23b36e10L, 0xd0f8b76a912c6bdeL)));

		SPECIAL_PARENT.add(new Pair<String, Pair<Long, Long>>("_memmove",
			new Pair<Long, Long>(0x33d1cb7adc1726dbL, 0xdbf9702ed06fc8faL)));
		SPECIAL_PARENT.add(new Pair<String, Pair<Long, Long>>("_memmove",
			new Pair<Long, Long>(0x33d1cb7adc1726dbL, 0xc75b9390823f17b8L)));
		SPECIAL_PARENT.add(new Pair<String, Pair<Long, Long>>("_memmove",
			new Pair<Long, Long>(0xcf7c351b23b36e10L, 0x0cc0176381fd7eebL)));
		SPECIAL_PARENT.add(new Pair<String, Pair<Long, Long>>("_memmove",
			new Pair<Long, Long>(0xcf7c351b23b36e10L, 0xb821796c54461d3dL)));
		AUTO_FAIL_REGEX.add("^\\$L.*");
	}

	/**
	 * Hash adjustments for 64-bit Visual Studio libraries
	 */
	private void buildKnownHashes64() {
		REMOVE_HASHES.add(fh(5, 0xa668ec55aef791ecL));		// ??$__crt_interlocked_read@H@@YAHPEDH@Z
		REMOVE_HASHES.add(fh(6, 0x744ed66532c779f8L));		// ??1?$CAtlArray@PEAXV?$CElementTraits@PEAX@ATL@@@ATL@@QEAA@XZ
		REMOVE_HASHES.add(fh(3, 0x73d3b025f0122566L));		// ??1Bitmap@Gdiplus@@UEAA@XZ
		REMOVE_HASHES.add(fh(13, 0x1371a69353a7828L));		// ??_GFreeVirtualProcessorRoot@details@Concurrency@@UEAAPEAXI@Z
		REMOVE_HASHES.add(fh(16, 0x81ce16d5bcd80d96L));		// ??_GCMFCVisualManagerBitmapCacheItem@CMFCVisualManagerBitmapCache@@UEAAPEAXI@Z
		REMOVE_HASHES.add(fh(9, 0x482f6a6b1c9a9bc5L));		// ??1CPropbagPropExchange@@UEAA@XZ
		REMOVE_HASHES.add(fh(11, 0x380756a1e4cbab8aL));		// ??1CMFCPropertyPage@@UEAA@XZ
		REMOVE_HASHES.add(fh(18, 0x8393f8fd57b9e43cL));		// ??_GCMFCCustomColorsPropertyPage@@UEAAPEAXI@Z
		REMOVE_HASHES.add(fh(12, 0x85a8f5c1bf2f96f5L));		// ?_Tidy@?$vector@EV?$allocator@E@std@@@std@@IEAAXXZ
		REMOVE_HASHES.add(fh(20, 0x9ff93e3930c33535L));		// ??_G?$ctype@G@std@@MEAAPEAXI@Z
		REMOVE_HASHES.add(fh(13, 0xfd681e45dcde824aL));		// ??1CMFCOutlookBarPane@@UEAA@XZ
		REMOVE_HASHES.add(fh(16, 0x64d27a7ffb0fc3a8L));		// ??_GBitmap@Gdiplus@@UEAAPEAXI@Z
		REMOVE_HASHES.add(fh(13, 0x2ecc70b4797c9810L));		// ??_G?$CArray@HAEBH@@UEAAPEAXI@Z
		REMOVE_HASHES.add(fh(20, 0x4878860cdc26f2bdL));		// ??_G?$basic_ostream@DU?$char_traits@D@std@@@std@@UEAAPEAXI@Z
		REMOVE_HASHES.add(fh(23, 0x545b08612c53fcf9L));		// ??0failure@ios_base@std@@QEAA@AEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@V_STL70@@@2@@Z
		REMOVE_HASHES.add(fh(5, 0xe522c1bfa12abc7cL));		// ??3CNoTrackObject@@SAXPEAX@Z
		REMOVE_HASHES.add(fh(17, 0xdddd776fd04f669L));		// ??_GCMiniDockFrameWnd@@UEAAPEAXI@Z
		REMOVE_HASHES.add(fh(22, 0xb2dbb68d07f64ca3L));		// ??_G_com_error@@UEAAPEAXI@Z
		REMOVE_HASHES.add(fh(10, 0x4f0b7cc769eb16f3L));		// ??1COleDispParams@@QEAA@XZ
		REMOVE_HASHES.add(fh(10, 0x510d2f08e95d5863L));		// ??1CRegKey@ATL@@QEAA@XZ
		REMOVE_HASHES.add(fh(20, 0xe1cf6ea84d56fb12L));		// ??_G?$numpunct@D@std@@MEAAPEAXI@Z
		REMOVE_HASHES.add(fh(19, 0xbb0a4a7803b8e830L));		// IERefreshElevationPolicy
		REMOVE_HASHES.add(fh(7, 0x41cab2108dd31ba7L));		// ==
		REMOVE_HASHES.add(fh(22, 0x27108c660568241bL));		// ??_Gfailure@ios_base@std@@UEAAPEAXI@Z
		REMOVE_HASHES.add(fh(10, 0x21fea5167b4a7083L));		// ??1CAnimateCtrl@@UEAA@XZ
		REMOVE_HASHES.add(fh(8, 0x89426b655ac79064L));		// ??1CMediaSample@@UEAA@XZ
		REMOVE_HASHES.add(fh(19, 0xf39cb68bc80f76f7L));		// ??_GUMSFreeThreadProxy@details@Concurrency@@UEAAPEAXI@Z
		REMOVE_HASHES.add(fh(20, 0xc9026b5e8e8d9ee8L));		// ??_GCOutlookOptionsDlg@@UEAAPEAXI@Z
		REMOVE_HASHES.add(fh(17, 0x230acc291fed10c5L));		// ??_GThreadInternalContext@details@Concurrency@@UEAAPEAXI@Z
		REMOVE_HASHES.add(fh(7, 0x1b004293e81305c4L));		// ??1?$CComPtr@UIAMAudioInputMixer@@@ATL@@QEAA@XZ
		REMOVE_HASHES.add(fh(16, 0xd42336b525605796L));		// ??_G_AFX_PROPPAGEFONTINFO@@UEAAPEAXI@Z
		REMOVE_HASHES.add(fh(17, 0x97fd3cf798f2bd15L));		// ??_GCMultiPageDHtmlDialog@@UEAAPEAXI@Z
		REMOVE_HASHES.add(fh(23, 0x1c009fbde7812ed5L));		// ??0failure@ios_base@std@@QEAA@AEBV012@@Z
		REMOVE_HASHES.add(fh(10, 0x7e10fbe69b976818L));		// ??1CAudioMediaType@@MEAA@XZ
		REMOVE_HASHES.add(fh(15, 0x79c797eb8032b47L));		// ??_G?$CList@IAEAI@@UEAAPEAXI@Z

		FORCE_RELATION.add(fh(6, 0x508d431b82512d5bL));		// Generic wrapper, one obvious child
		FORCE_RELATION.add(fh(19, 0x1e68c4d4d83e7585L));	// A little too generic stream thing, force parent
		FORCE_RELATION.add(fh(26, 0xca6253ab6d6a32beL));	// Count decrement dispatcher, distinguish via parent
		FORCE_RELATION.add(fh(18, 0x9c1597a636ea13b3L));	// scalar_deleting_destructor with a child
		FORCE_RELATION.add(fh(15, 0x85b697ef56707979L));	// Generic form with one child
		FORCE_RELATION.add(fh(15, 0xe27b2550f3b616bcL));	// Generic form, force parent match
		FORCE_RELATION.add(fh(14, 0xa2b429ca49281059L));	// Generic destructor with one child
		FORCE_RELATION.add(fh(21, 0x5eae3016f3cc4caaL));	// Common destructor form (only child is free)
		FORCE_RELATION.add(fh(12, 0xe77f57508779c258L));	// Generic assign
		FORCE_RELATION.add(fh(18, 0x61950fc199f518fL));		// Generic destructor with children
		FORCE_RELATION.add(fh(25, 0x6a5c4f8adc931359L));	// scalar_deleting_destructor force parent
		FORCE_RELATION.add(fh(13, 0xf1e4167aedf569aL));		// Generic form, with many children
		FORCE_RELATION.add(fh(20, 0x678b611a60783c98L));	// Generic form with children

		FORCE_SPECIFIC.add(fh(26, 0xf0f7f2439683bfeaL));	// Variants with specialized constants
		FORCE_SPECIFIC.add(fh(17, 0xf468f6c40495d8caL));	// Dispatcher form with lots of specific constants
		FORCE_SPECIFIC.add(fh(13, 0x8779436db6c1d90L));		// ??1?$basic_string@GU?$char_traits@G@std@@V?$allocator@G@2@V_STL70@@@std@@QEAA@XZ
		FORCE_SPECIFIC.add(fh(75, 0x48156d182763009dL));	// _write confused with _read
		FORCE_SPECIFIC.add(fh(51, 0x5c02a83d7b53cabbL));	// ??1CCommandLineInfo@@UEAA@XZ

		FORCE_SPECIFIC.add(fh(10, 0x5c4a91ec77ecc3d2L));	// strnlen
		AUTO_PASS.add(fh(10, 0x5c4a91ec77ecc3d2L));
		FORCE_SPECIFIC.add(fh(11, 0x7069490c2c75ca8fL));	// ?AllocateHeap@?$CTempBuffer@D$0IA@VCCRTAllocator@ATL@@@ATL@@AEAAX_K@Z
		AUTO_PASS.add(fh(11, 0x7069490c2c75ca8fL));
		FORCE_SPECIFIC.add(fh(9, 0x9fdcae243f10941bL));		// ?AtlThrowImpl@ATL@@YAXJ@Z
		AUTO_PASS.add(fh(9, 0x9fdcae243f10941bL));
		FORCE_SPECIFIC.add(fh(10, 0xaba76591680821c6L));	// strnlen
		AUTO_PASS.add(fh(10, 0xaba76591680821c6L));
		FORCE_SPECIFIC.add(fh(10, 0x6244ea7ccad27b93L));	// wcsnlen
		AUTO_PASS.add(fh(10, 0x6244ea7ccad27b93L));
	}

	private static Pair<Short, Long> fh(int codeUnits, long digest) {
		Pair<Short, Long> result = new Pair<>((short) codeUnits, digest);
		return result;
	}

	@Override
	protected void run() throws Exception {
		FidFileManager fidFileManager = FidFileManager.getInstance();

		List<FidFile> allKnownFidFiles = fidFileManager.getFidFiles();
		ArrayList<String> dbfiles = new ArrayList<>();
		HashMap<String, FidFile> fidMap = new HashMap<>();
		for (FidFile fidFile : allKnownFidFiles) {
			if (!fidFile.isInstalled()) {
				fidMap.put(fidFile.getName(), fidFile);
				dbfiles.add(fidFile.getName());
			}
		}
		String[] nameArray = new String[dbfiles.size()];
		dbfiles.toArray(nameArray);
		String askChoice = askChoice("RemoveFunctions script", "Choose FID database: ",
			Arrays.asList(nameArray), nameArray[0]);
		FidFile fidFile = fidMap.get(askChoice);
		FidDB modifiableFidDB = fidFile.getFidDB(true);
		List<LibraryRecord> allLibraries = modifiableFidDB.getAllLibraries();
		boolean is64bit = false;
		boolean is32bit = false;
		for (LibraryRecord rec : allLibraries) {
			if (rec.getGhidraLanguageID().getIdAsString().startsWith("x86:LE:64")) {
				is64bit = true;
			}
			else if (rec.getGhidraLanguageID().getIdAsString().startsWith("x86:LE:32")) {
				is32bit = true;
			}
		}
		if (is32bit && is64bit) {
			throw new IOException(
				"Script can only process code of one type (32-bit or 64-bit) at a time");
		}
		if ((!is32bit) && (!is64bit)) {
			throw new IOException(
				"Script is designed to run only on a FID database generated from x86 code");
		}
		if (is64bit) {
			buildKnownHashes64();
		}
		else {
			buildKnownHashes32();
		}
		try {
			monitor.setMaximum(AUTO_FAIL_REGEX.size());
			monitor.setProgress(0);
			for (String regex : AUTO_FAIL_REGEX) {
				monitor.checkCanceled();
				monitor.incrementProgress(1);
				List<FunctionRecord> recordList = modifiableFidDB.findFunctionsByNameRegex(regex);
				for (FunctionRecord record : recordList) {
					modifiableFidDB.setAutoFailOnFunction(record, true);
				}
			}
			monitor.setMaximum(SPECIAL_PARENT.size());
			monitor.setProgress(0);
			for (Pair<String, Pair<Long, Long>> pair : SPECIAL_PARENT) {
				monitor.checkCanceled();
				monitor.incrementProgress(1);
				List<FunctionRecord> childFunctions =
					modifiableFidDB.findFunctionsByFullHash(pair.second.first);
				List<FunctionRecord> parentFunctions =
					modifiableFidDB.findFunctionsByFullHash(pair.second.second);
				if (parentFunctions.isEmpty()) {
					continue;
				}
				FunctionRecord parentFunction = parentFunctions.get(0);
				for (FunctionRecord childFunction : childFunctions) {
					if (!childFunction.getName().equals(pair.first)) {
						continue;
					}
					modifiableFidDB.createInferiorRelation(parentFunction, childFunction);
				}
			}
			monitor.setMaximum(REMOVE_HASHES.size());
			monitor.setProgress(0);
			for (Pair<Short, Long> pair : REMOVE_HASHES) {
				modifiableFidDB.setAutoFailByFullHash(pair.second.longValue(), true);
				monitor.checkCanceled();
				monitor.incrementProgress(1);
			}
			monitor.setMaximum(FORCE_RELATION.size());
			monitor.setProgress(0);
			for (Pair<Short, Long> pair : FORCE_RELATION) {
				modifiableFidDB.setForceRelationByFullHash(pair.second.longValue(), true);
				monitor.checkCanceled();
				monitor.incrementProgress(1);
			}
			monitor.setMaximum(FORCE_SPECIFIC.size());
			monitor.setProgress(0);
			for (Pair<Short, Long> pair : FORCE_SPECIFIC) {
				modifiableFidDB.setForceSpecificByFullHash(pair.second.longValue(), true);
				monitor.checkCanceled();
				monitor.incrementProgress(1);
			}
			monitor.setMaximum(AUTO_PASS.size());
			monitor.setProgress(0);
			for (Pair<Short, Long> pair : AUTO_PASS) {
				modifiableFidDB.setAutoPassByFullHash(pair.second.longValue(), true);
				monitor.checkCanceled();
				monitor.incrementProgress(1);
			}

			modifiableFidDB.saveDatabase("", monitor);
		}
		finally {
			modifiableFidDB.close();
		}
	}
}
