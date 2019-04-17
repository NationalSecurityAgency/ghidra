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
#include "paramid.hh"

// NOTES FROM 20121206 W/Decompiler-Man
// direct reads is for all opcodes, with special for these:
// BRANCH is direct read on input0.  No direct write.
// CBRANCH is direct read on input0 and input1.  No direct write.
// BRANCHIND is direct read on input0 (like call but no params).  No direct write.
// CALL is direct read on input0 (putative/presumptive param flag on params--other inputs).  Special (non-direct) write of output.
// CALLIND same as on CALL.  Special (non-direct) write of output.
// CALLOTHER is direct read on ALL PARAMETERS (input0 and up)--is specified in sleigh.  Direct write if output exists.
// INDIRECT is least powerful input and output of all.
// MULTIEQUALS is flow through but must test for and not flow through loop paths (whether from param forward our return backward directions).
//

#define MAXDEPTH        10
void ParamMeasure::walkforward( WalkState &state, PcodeOp *ignoreop, Varnode *vn )

{
  state.depth += 1;
  if (state.depth >= MAXDEPTH) {
    state.depth -= 1;
    return;
  }
  list<PcodeOp *>::const_iterator iter = vn->beginDescend();
  while( rank != state.terminalrank && iter != vn->endDescend() ) {
    PcodeOp *op = *iter;
    if( op != ignoreop ) {
      OpCode oc = op->getOpcode()->getOpcode();
      switch( oc ) {
      case CPUI_BRANCH:
      case CPUI_BRANCHIND:
	if( op->getSlot(vn) == 0 ) updaterank( DIRECTREAD, state.best );
	break;
      case CPUI_CBRANCH:
        if( op->getSlot(vn) < 2 ) updaterank( DIRECTREAD, state.best );
        break;
      case CPUI_CALL:
      case CPUI_CALLIND:
        if( op->getSlot(vn) == 0 ) updaterank( DIRECTREAD, state.best );
        else {
          numcalls++;
          updaterank( SUBFNPARAM, state.best );
        }
        break;
      case CPUI_CALLOTHER:
        updaterank( DIRECTREAD, state.best );
        break;
      case CPUI_RETURN:
        updaterank( THISFNRETURN, state.best );
        break;
      case CPUI_INDIRECT:
        updaterank( INDIRECT, state.best );
        break;
      case CPUI_MULTIEQUAL:
        // The only op for which there can be a loop in the graph is with the MULTIEQUAL (not for CALL, etc.).
        // Walk forward only if the path is not part of a loop.
        if( !op->getParent()->isLoopIn(op->getSlot(vn)) ) walkforward( state, (PcodeOp *)0, op->getOut() );
        break;
      default:
        updaterank( DIRECTREAD, state.best );
        break;
      }
    }
    iter++;
  }
  state.depth -= 1;
}

void ParamMeasure::walkbackward( WalkState &state, PcodeOp *ignoreop, Varnode *vn )

{
  if( vn->isInput() ) {
    updaterank( THISFNPARAM, state.best );
    return;
  }
  else if( !vn->isWritten() ) {
    updaterank( THISFNPARAM, state.best ); //TODO: not sure about this.
    return;
  }
  
  PcodeOp *op = vn->getDef();
  OpCode oc = op->getOpcode()->getOpcode();
  switch( oc ) {
  case CPUI_BRANCH:
  case CPUI_BRANCHIND:
  case CPUI_CBRANCH:
  case CPUI_CALL:
  case CPUI_CALLIND:
    break;
  case CPUI_CALLOTHER:
    if( op->getOut() != (Varnode *) 0 ) updaterank( DIRECTREAD, state.best );
    break;
  case CPUI_RETURN:
    updaterank( SUBFNRETURN, state.best );
    break;
  case CPUI_INDIRECT:
    updaterank( INDIRECT, state.best );
    break;
  case CPUI_MULTIEQUAL:
    // The only op for which there can be a loop in the graph is with the MULTIEQUAL (not for CALL, etc.).
    // Walk backward only if the path is not part of a loop.
    for( int4 slot = 0; slot < op->numInput() && rank != state.terminalrank; slot++ )
      if( !op->getParent()->isLoopIn(slot) ) walkbackward( state, op, op->getIn(slot) );
    break;
  default:
    //Might be DIRECTWRITEWITHOUTREAD, but we do not know yet.
    //So now try to walk forward to see if there is at least one path
    // forward (other than the path we took to get here walking backward)
    // in which there is not a direct read of this write.
    ParamMeasure pmfw( vn->getAddr(), vn->getSize(), vn->getType(), INPUT );
    pmfw.calculateRank( false, vn, ignoreop );
    if( pmfw.getMeasure() == DIRECTREAD )
      updaterank( DIRECTWRITEWITHREAD, state.best );
    else
      updaterank( DIRECTWRITEWITHOUTREAD, state.best );
    break;
  }
}

void ParamMeasure::calculateRank(bool best,Varnode *basevn,PcodeOp *ignoreop)

{
  WalkState state;
  state.best = best;
  state.depth = 0;
  if( best ) {
    rank = WORSTRANK;
    state.terminalrank = (io == INPUT) ? DIRECTREAD : DIRECTWRITEWITHOUTREAD;
  } else {
    rank = BESTRANK;
    state.terminalrank = INDIRECT;
  }
  numcalls = 0;
  if (io == INPUT)
    walkforward(state, ignoreop, basevn);
  else
    walkbackward(state, ignoreop, basevn);
}

void ParamMeasure::saveXml( ostream &s,string tag,bool moredetail ) const

{
  s << "<" + tag +">\n<addr";
  vndata.space->saveXmlAttributes( s, vndata.offset, vndata.size );
  s << "/>\n";
  vntype->saveXml(s);
  if( moredetail ) {
    s << "<rank";
    a_v_i(s,"val",rank);
    s << "/>";
  }
  s << "</" + tag + ">\n";
}

void ParamMeasure::savePretty( ostream &s,bool moredetail ) const

{
  s << "  Space: " << vndata.space->getName() << "\n";
  s << "  Addr: " << vndata.offset << "\n";
  s << "  Size: " << vndata.size << "\n";
  s << "  Rank: " << rank << "\n";
}

ParamIDAnalysis::ParamIDAnalysis( Funcdata *fd_in, bool justproto )

{
  fd = fd_in;
  if (justproto) {		// We only provide info on the recovered prototype
    const FuncProto &fproto( fd->getFuncProto() );
    int4 num = fproto.numParams();
    for(int4 i=0;i<num;++i) {
      ProtoParameter *param = fproto.getParam(i);
      InputParamMeasures.push_back( ParamMeasure(param->getAddress(),param->getSize(),
						 param->getType(),ParamMeasure::INPUT) );
      Varnode *vn = fd->findVarnodeInput(param->getSize(),param->getAddress());
      if (vn != (Varnode *)0)
	InputParamMeasures.back().calculateRank(true,vn,(PcodeOp *)0);
    }

    ProtoParameter *outparam = fproto.getOutput();
    if (!outparam->getAddress().isInvalid()) { // If we don't have a void type
      OutputParamMeasures.push_back( ParamMeasure( outparam->getAddress(),outparam->getSize(),
						   outparam->getType(),ParamMeasure::OUTPUT) );
      list<PcodeOp *>::const_iterator rtn_iter = fd->beginOp( CPUI_RETURN );
      while( rtn_iter != fd->endOp( CPUI_RETURN ) ) {
	PcodeOp *rtn_op = *rtn_iter;
	// For RETURN op, input0 is address location of indirect return, input1,
        // if it exists, is the Varnode returned, output = not sure.
	if( rtn_op->numInput() == 2 ) {
	  Varnode *ovn = rtn_op->getIn(1);
	  if( ovn != (Varnode *)0 ) {  //Not a void return
	    OutputParamMeasures.back().calculateRank(true, ovn, rtn_op );
	    break;
	  }
	}
	rtn_iter++;
      }
    }
  }
  else {
    // Need to list input varnodes that are outside of the model
    VarnodeDefSet::const_iterator iter,enditer;
    iter = fd->beginDef(Varnode::input);
    enditer = fd->endDef(Varnode::input);
    while(iter != enditer) {
      Varnode *invn = *iter;
      ++iter;
      InputParamMeasures.push_back( ParamMeasure(invn->getAddr(),invn->getSize(),
						 invn->getType(),ParamMeasure::INPUT) );
      InputParamMeasures.back().calculateRank(true, invn, (PcodeOp *)0 );
    }
  }
}

void ParamIDAnalysis::saveXml( ostream &s,bool moredetail ) const

{
  s << "<parammeasures";
  a_v( s, "name", fd->getName() );
  s << ">\n  ";
  fd->getAddress().saveXml( s );
  s << "\n  <proto";

  a_v(s,"model", fd->getFuncProto().getModelName());
  int4 extrapop = fd->getFuncProto().getExtraPop();
  if (extrapop == ProtoModel::extrapop_unknown)
    a_v(s,"extrapop","unknown");
  else
    a_v_i(s,"extrapop",extrapop);
  s << "/>\n";
  list<ParamMeasure>::const_iterator pm_iter;
  for( pm_iter = InputParamMeasures.begin(); pm_iter != InputParamMeasures.end(); ++pm_iter) {
    const ParamMeasure &pm( *pm_iter );
    s << "  ";
    pm.saveXml(s,"input",moredetail);
  }
  for( pm_iter = OutputParamMeasures.begin(); pm_iter != OutputParamMeasures.end() ; ++pm_iter) {
    const ParamMeasure &pm( *pm_iter );
    s << "  ";
    pm.saveXml( s, "output", moredetail );
  }
  s << "</parammeasures>";
  s << "\n";
}

void ParamIDAnalysis::savePretty( ostream &s,bool moredetail ) const

{
  s << "Param Measures\nFunction: " << fd->getName() << "\nAddress: 0x" << hex << fd->getAddress().getOffset() << "\n";
  s << "Model: " << fd->getFuncProto().getModelName() << "\nExtrapop: " << fd->getFuncProto().getExtraPop() << "\n";
  s << "Num Params: " << InputParamMeasures.size() << "\n";
  list<ParamMeasure>::const_iterator pm_iter = InputParamMeasures.begin();
  for( pm_iter = InputParamMeasures.begin(); pm_iter != InputParamMeasures.end() ; ++pm_iter ) {
    const ParamMeasure &pm( *pm_iter );
    pm.savePretty( s, moredetail );
  }
  s << "Num Returns: " << OutputParamMeasures.size() << "\n";
  pm_iter = OutputParamMeasures.begin();
  for( pm_iter = OutputParamMeasures.begin(); pm_iter != OutputParamMeasures.end() ; ++pm_iter) {
    const ParamMeasure &pm( *pm_iter );
    pm.savePretty( s, moredetail );
  }
  s << "\n";
}
