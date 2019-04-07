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
#ifndef __PREFERSPLIT__
#define __PREFERSPLIT__

#include "varnode.hh"
class Funcdata;			// Forward declaration

struct PreferSplitRecord {
  VarnodeData storage;
  int4 splitoffset;		// Number of initial bytes (in address order) to split into first piece
  bool operator<(const PreferSplitRecord &op2) const;
};

class PreferSplitManager {
  class SplitInstance {
    friend class PreferSplitManager;
    int4 splitoffset;
    Varnode *vn;
    Varnode *hi;	// Most significant piece
    Varnode *lo;	// Least significant piece
  public:
    SplitInstance(Varnode *v,int4 off) { vn = v; splitoffset = off; hi = (Varnode *)0; lo = (Varnode *)0; }
  };
  Funcdata *data;
  const vector<PreferSplitRecord> *records;
  vector<PcodeOp *> tempsplits; // Copies of temporaries that need additional splitting
  void fillinInstance(SplitInstance *inst,bool bigendian,bool sethi,bool setlo);
  void createCopyOps(SplitInstance *ininst,SplitInstance *outinst,PcodeOp *op,bool istemp);
  bool testDefiningCopy(SplitInstance *inst,PcodeOp *def,bool &istemp);
  void splitDefiningCopy(SplitInstance *inst,PcodeOp *def,bool istemp);
  bool testReadingCopy(SplitInstance *inst,PcodeOp *readop,bool &istemp);
  void splitReadingCopy(SplitInstance *inst,PcodeOp *readop,bool istemp);
  bool testZext(SplitInstance *inst,PcodeOp *op);
  void splitZext(SplitInstance *inst,PcodeOp *op);
  bool testPiece(SplitInstance *inst,PcodeOp *op);
  void splitPiece(SplitInstance *inst,PcodeOp *op);
  bool testSubpiece(SplitInstance *inst,PcodeOp *op);
  void splitSubpiece(SplitInstance *inst,PcodeOp *op);
  bool testLoad(SplitInstance *inst,PcodeOp *op);
  void splitLoad(SplitInstance *inst,PcodeOp *op);
  bool testStore(SplitInstance *inst,PcodeOp *op);
  void splitStore(SplitInstance *inst,PcodeOp *op);
  bool splitVarnode(SplitInstance *inst);
  void splitRecord(const PreferSplitRecord &rec);
  bool testTemporary(SplitInstance *inst);
  void splitTemporary(SplitInstance *inst);
public:
  void init(Funcdata *fd,const vector<PreferSplitRecord> *rec);
  const PreferSplitRecord *findRecord(Varnode *vn) const;
  static void initialize(vector<PreferSplitRecord> &records);
  void split(void);
  void splitAdditional(void);
};

#endif
