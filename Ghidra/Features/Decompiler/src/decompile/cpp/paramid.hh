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
#ifndef __CPUI_PARAMID__
#define __CPUI_PARAMID__

#include "funcdata.hh"

class ParamMeasure {
public:
  enum ParamIDIO {
    INPUT = 0,
    OUTPUT = 1
  };
  enum ParamRank {
    BESTRANK = 1,
    DIRECTWRITEWITHOUTREAD = 1, //Output
    DIRECTREAD = 2,             //Input.  Must be same as DIRECTWRITEWITHREAD so that walkforward as part of walkbackward works
                                //  for detecting(not that DIRECTREAD is lower rank that DIRECTWRITEWITHOUTREAD)
    DIRECTWRITEWITHREAD = 2,    //Output
    DIRECTWRITEUNKNOWNREAD = 3, //Output
    SUBFNPARAM = 4,             //Input
    THISFNPARAM = 4,            //Output
    SUBFNRETURN = 5,            //Output
    THISFNRETURN = 5,		//Input
    INDIRECT = 6,		//Input or Output
    WORSTRANK = 7
  };
  struct WalkState {
    bool best;
    int4 depth;
    ParamRank terminalrank;
  };
private:
  VarnodeData vndata;
  Datatype *vntype;
  ParamRank rank;
  ParamIDIO io;
  int4 numcalls;
  void walkforward( WalkState &state, PcodeOp *ignoreop, Varnode *vn );
  void walkbackward( WalkState &state, PcodeOp *ignoreop,Varnode *vn );
  void updaterank( ParamRank rank_in,bool best ) { rank = (best==true) ? min( rank, rank_in ) : max( rank, rank_in ); }
public:
  ParamMeasure( const Address &addr, int4 sz, Datatype *dt, ParamIDIO io_in) {
    vndata.space=addr.getSpace(); vndata.offset=addr.getOffset(); vndata.size = sz; vntype=dt; io = io_in; rank=WORSTRANK; }
  void calculateRank(bool best,Varnode *basevn,PcodeOp *ignoreop);
  void saveXml( ostream &s,string tag,bool moredetail ) const;
  void savePretty( ostream &s,bool moredetail ) const;
  int4 getMeasure(void) const { return (int4) rank; }
};

class ParamIDAnalysis
{
  Funcdata *fd;
  list<ParamMeasure> InputParamMeasures;
  list<ParamMeasure> OutputParamMeasures;
public:
  ParamIDAnalysis( Funcdata *fd_in, bool justproto );
  void saveXml( ostream &s, bool moredetail ) const;
  void savePretty( ostream &s, bool moredetail ) const;
};

#endif //ifndef __CPUI_PARAMID__
