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
/// \file prefersplit.hh
/// \brief Classes for performing splits of raw Varnodes (and PcodeOps) based on explicit records

#ifndef __PREFERSPLIT_HH__
#define __PREFERSPLIT_HH__

#include "varnode.hh"

namespace ghidra {

class Funcdata;			// Forward declaration

extern ElementId ELEM_PREFERSPLIT;	///< Marshaling element \<prefersplit>

/// \brief An address range and the point where it should be split
struct PreferSplitRecord {
  VarnodeData storage;		///< The address range to split
  int4 splitoffset;		///< Number of initial bytes (in address order) to split into first piece
  bool operator<(const PreferSplitRecord &op2) const;
};

/// \brief Split a designated list of registers or other address ranges in two
///
/// Splitting happens prior to Heritage process to simplify the transformations.
///   - out = COPY(in) is split into lo_out = COPY(lo_in) and hi_out = COPY(hi_in).
///   - ZEXT(in) is split into lo_out = COPY(in) and hi_out = COPY(0).
///   - PIECE(hi_in,hi_out) is split into lo_out = COPY(lo_in) and hi_out = COPY(hi_in).
///   - out = SUBPIECE(in,\#0) becomes out = COPY(lo_in).
///   - out = SUBPIECE(in,\#hi) becomes out = COPY(hi_in).
///   - out = LOAD(ptr) is split into out_lo = LOAD(ptr+\#looff) and out_hi = LOAD(ptr+\#hioff).
///   - STORE(ptr,in) is split into STORE(ptr+\#looff,in_lo) and STORE(ptr+\#hioff,in_hi)
///
/// After the heritage pass, splitAdditional() can split additional Varnodes linked to the original
/// split Varnodes through COPYs to \e unique Varnodes.
///
/// A Varnode can be split recursively into more than two pieces, if two or more overlapping split records are present.
class PreferSplitManager {
  /// \brief A Varnode being split and its two pieces
  class SplitInstance {
    friend class PreferSplitManager;
    int4 splitoffset;	///< Number of initial bytes (in address order) to split into first piece
    Varnode *vn;	///< Varnode being split
    Varnode *hi;	///< Most significant piece
    Varnode *lo;	///< Least significant piece
  public:
    SplitInstance(Varnode *v,int4 off) { vn = v; splitoffset = off; hi = (Varnode *)0; lo = (Varnode *)0; }	///< Constructor
    void createPieces(Funcdata *data,bool sethi,bool setlo);
  };
  Funcdata *data;				///< Function splitting is applied to
  const vector<PreferSplitRecord> *records;	///< Specified address ranges to split
  vector<PcodeOp *> tempsplits; 		///< Copies of temporaries that need additional splitting
  void createCopyOps(SplitInstance &ininst,SplitInstance &outinst,PcodeOp *op);
  bool testDefiningCopy(SplitInstance &inst,PcodeOp *def);
  void splitDefiningCopy(SplitInstance &inst,PcodeOp *def);
  bool testReadingCopy(SplitInstance &inst,PcodeOp *readop);
  void splitReadingCopy(SplitInstance &inst,PcodeOp *readop);
  bool testZext(SplitInstance &inst,PcodeOp *op);
  void splitZext(SplitInstance &inst,PcodeOp *op);
  bool testPiece(SplitInstance &inst,PcodeOp *op);
  void splitPiece(SplitInstance &inst,PcodeOp *op);
  bool testSubpiece(SplitInstance &inst,PcodeOp *op);
  void splitSubpiece(SplitInstance &inst,PcodeOp *op);
  bool testLoad(SplitInstance &inst,PcodeOp *op);
  void splitLoad(SplitInstance &inst,PcodeOp *op);
  bool testStore(SplitInstance &inst,PcodeOp *op);
  void splitStore(SplitInstance &inst,PcodeOp *op);
  bool splitVarnode(SplitInstance &inst);
  void splitRecord(const PreferSplitRecord &rec);
  bool testTemporary(SplitInstance &inst);
  void splitTemporary(SplitInstance &inst);
public:
  void init(Funcdata *fd,const vector<PreferSplitRecord> *rec);
  const PreferSplitRecord *findRecord(Varnode *vn) const;
  static void initialize(vector<PreferSplitRecord> &records);
  void split(void);
  void splitAdditional(void);
};

} // End namespace ghidra
#endif
