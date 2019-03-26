/* ###
 * IP: GHIDRA
 * NOTE: Serializes graphs in format used by Renoir
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
#include "graph.hh"

static void print_varnode_vertex(Varnode *vn,ostream &s)

{
  PcodeOp *op;

  if (vn == (Varnode *)0) return;
  if (vn->isMark()) return;
  AddrSpace *spc = vn->getSpace();
  if (spc->getType() == IPTR_FSPEC) return;
  if (spc->getType() == IPTR_IOP) return;
  s << dec << 'v' << vn->getCreateIndex() << ' ' << spc->getName();
  s << " var ";

  vn->printRawNoMarkup(s);

  op = vn->getDef();
  if (op != (PcodeOp *)0)
    s << ' ' << hex << op->getAddr().getOffset();
  else if (vn->isInput())
    s << " i";
  else
    s << " <na>";
  s << endl;
  vn->setMark();
}
  
static void print_op_vertex(PcodeOp *op,ostream &s)

{
  s << dec << 'o' << op->getTime() << ' ';
  if (op->isBranch())
    s << "branch";
  else if (op->isCall())
    s << "call";
  else if (op->isMarker())
    s << "marker";
  else
    s << "basic";
  s << " op ";
  if (!op->getOpName().empty())
    s << op->getOpName();
  else
    s << "unkop";
  s << ' ' << hex << op->getAddr().getOffset();
  s << endl;
}

static void dump_varnode_vertex(Funcdata &data,ostream &s)

{
  list<PcodeOp *>::const_iterator oiter;
  PcodeOp *op;
  int4 i,start,stop;

  s << "\n\n// Add Vertices\n";
  s << "*CMD=*COLUMNAR_INPUT,\n";
  s << "  Command=AddVertices,\n";
  s << "  Parsing=WhiteSpace,\n";
  s << "  Fields=({Name=Internal, Location=1},\n";
  s << "          {Name=SubClass, Location=2},\n";
  s << "          {Name=Type, Location=3},\n";
  s << "          {Name=Name, Location=4},\n";
  s << "          {Name=Address, Location=5});\n\n";
  s << "//START:varnodes\n";

  for(oiter=data.beginOpAlive();oiter!=data.endOpAlive();++oiter) {
    op = *oiter;
    print_varnode_vertex(op->getOut(),s);
    start = 0;
    stop = op->numInput();
    switch(op->code()) {
    case CPUI_LOAD:
    case CPUI_STORE:
    case CPUI_BRANCH:
    case CPUI_CALL:
      start = 1;
      break;
    case CPUI_INDIRECT:
      stop = 1;
      break;
    default:
      break;
    }
    for(i=start;i<stop;++i)
      print_varnode_vertex(op->getIn(i),s);
  }
  s << "*END_COLUMNS\n";
  for(oiter=data.beginOpAlive();oiter!=data.endOpAlive();++oiter) {
    op = *oiter;
    if (op->getOut()!=(Varnode *)0)
      op->getOut()->clearMark();
    for(i=0;i<op->numInput();++i)
      op->getIn(i)->clearMark();
  }
}
 
static void dump_op_vertex(Funcdata &data,ostream &s)

{   
  list<PcodeOp *>::const_iterator oiter;
  PcodeOp *op;

  s << "\n\n// Add Vertices\n";
  s << "*CMD=*COLUMNAR_INPUT,\n";
  s << "  Command=AddVertices,\n";
  s << "  Parsing=WhiteSpace,\n";
  s << "  Fields=({Name=Internal, Location=1},\n";
  s << "          {Name=SubClass, Location=2},\n";
  s << "          {Name=Type, Location=3},\n";
  s << "          {Name=Name, Location=4},\n";
  s << "          {Name=Address, Location=5});\n\n";
  s << "//START:opnodes\n";

  for(oiter=data.beginOpAlive();oiter!=data.endOpAlive();++oiter) {
    op = *oiter;
    print_op_vertex(op,s);
  }
  s << "*END_COLUMNS\n";
}

static void print_edges(PcodeOp *op,ostream &s)

{
  Varnode *vn;
  int4 i,start,stop;

  vn = op->getOut();
  if (vn != (Varnode *)0)
    s << dec << 'o' << op->getTime() << " v" << vn->getCreateIndex() << " output\n";
  start = 0;
  stop = op->numInput();
  switch(op->code()) {
  case CPUI_LOAD:
  case CPUI_STORE:
  case CPUI_BRANCH:
  case CPUI_CALL:
    start = 1;
    break;
  case CPUI_INDIRECT:
    stop = 1;
    break;
  default:
    break;
  }
  for(i=start;i<stop;++i) {
    vn = op->getIn(i);
    spacetype tp = vn->getSpace()->getType();
    if ((tp != IPTR_FSPEC)&&(tp != IPTR_IOP))
      s << dec << 'v' << vn->getCreateIndex() << " o" << op->getTime() << " input\n";
  }
}

static void dump_edges(Funcdata &data,ostream &s)

{   
  list<PcodeOp *>::const_iterator oiter;
  PcodeOp *op;

  s << "\n\n// Add Edges\n";
  s << "*CMD=*COLUMNAR_INPUT,\n";
  s << "  Command=AddEdges,\n";
  s << "  Parsing=WhiteSpace,\n";
  s << "  Fields=({Name=*FromKey, Location=1},\n";
  s << "          {Name=*ToKey, Location=2},\n";
  s << "          {Name=Name, Location=3});\n\n";
  s << "//START:edges\n";

  for(oiter=data.beginOpAlive();oiter!=data.endOpAlive();++oiter) {
    op = *oiter;
    print_edges(op,s);
  }
  s << "*END_COLUMNS\n";
}

void dump_dataflow_graph(Funcdata &data,ostream &s)

{
  s << "*CMD=NewGraphWindow, WindowName=" << data.getName() << "-dataflow;\n";
  s << "*CMD=*NEXUS,Name=" << data.getName() << "-dataflow;\n";

  s << "\n// AutomaticArrangement\n";
  s << "  *CMD = AlterLocalPreferences, Name = AutomaticArrangement,\n";
  s << "  ~ReplaceAllParams = TRUE,\n";
  s << "  EnableAutomaticArrangement=true,\n";
  s << "  OnlyActOnVerticesWithoutCoordsIfOff=false,\n";
  s << "  DontUpdateMediumWithUserArrangement=false,\n";
  s << "  UserAddedArrangmentParams=({ServiceName=SimpleHierarchyFromSources,ServiceParams={~SkipPromptForParams=true}}),\n";
  s << "  SmallSize=50,\n";
  s << "  DontUpdateLargeWithUserArrangement=true,\n";
  s << "  NewVertexActionIfOff=ArrangeByMDS,\n";
  s << "  MediumSizeArrangement=SimpleHierarchyFromSources,\n";
  s << "  SmallSizeArrangement=SimpleHierarchyFromSources,\n";
  s << "  MediumSize=800,\n";
  s << "  LargeSizeArrangement=ArrangeInCircle,\n";
  s << "  DontUpdateSmallWithUserArrangement=false,\n";
  s << "  ActionSizeGainIfOff=1.0;\n";
  
  s << "\n// VertexColors\n";
  s << "  *CMD = AlterLocalPreferences, Name = VertexColors,\n";
  s << "  ~ReplaceAllParams = TRUE,\n";
  s << "  Mapping=({DisplayChoice=Magenta,AttributeValue=branch},\n";
  s << "  {DisplayChoice=Blue,AttributeValue=register},\n";
  s << "  {DisplayChoice=Black,AttributeValue=unique},\n";
  s << "  {DisplayChoice=DarkGreen,AttributeValue=const},\n";
  s << "  {DisplayChoice=DarkOrange,AttributeValue=ram},\n";
  s << "  {DisplayChoice=Orange,AttributeValue=stack}),\n";
  s << "  ChoiceForValueNotCovered=Red,\n";
  s << "  Extraction=CompleteValue,\n";
  s << "  ExtractionParams={},\n";
  s << "  AttributeName=SubClass,\n";
  s << "  ChoiceForMissingValue=Red,\n";
  s << "  CanOverride=true,\n";
  s << "  OverrideAttributeName=Color,\n";
  s << "  UsingRange=false;\n";

  s << "\n//     VertexIcons\n";
  s << "  *CMD = AlterLocalPreferences, Name = VertexIcons,\n";
  s << "  ~ReplaceAllParams = TRUE,\n";
  s << "  Mapping=({DisplayChoice=Circle,AttributeValue=var},\n";
  s << "  {DisplayChoice=Square,AttributeValue=op}),\n";
  s << "  ChoiceForValueNotCovered=Circle,\n";
  s << "  Extraction=CompleteValue,\n";
  s << "  ExtractionParams={},\n";
  s << "  AttributeName=Type,\n";
  s << "  ChoiceForMissingValue=Circle,\n";
  s << "  CanOverride=true,\n";
  s << "  OverrideAttributeName=Icon,\n";
  s << "  UsingRange=false;\n";

  s << "\n//     VertexLabels\n";
  s << "  *CMD = AlterLocalPreferences, Name = VertexLabels,\n";
  s << "  ~ReplaceAllParams = TRUE,\n";
  s << "  Center=({SpecialColor=Black,SpecialFontName=SansSerif,Format=StandardFormat,UseSpecialFontName=false,LabelAlignment=Center,TreatBackSlashNAsNewLine=false,MaxLines=4,FontSize=10,IncludeBackground=false,SqueezeLinesTogether=true,BackgroundColor=Black,UseSpecialColor=false,AttributeName=Name,MaxWidth=100}),\n";
  s << "  East=(),\n";
  s << "  SouthEast=(),\n";
  s << "  North=(),\n";
  s << "  West=(),\n";
  s << "  SouthWest=(),\n";
  s << "  NorthEast=(),\n";
  s << "  South=(),\n";
  s << "  NorthWest=();\n";

  s << "\n// Attributes\n";
  s << "*CMD=DefineAttribute,\n";
  s << "        Name=SubClass,\n";
  s << "        Type=String,\n";
  s << "        Category=Vertices;\n\n";
  s << "*CMD=DefineAttribute,\n";
  s << "        Name=Type,\n";
  s << "        Type=String,\n";
  s << "        Category=Vertices;\n\n";
  s << "*CMD=DefineAttribute,\n";
  s << "        Name=Internal,\n";
  s << "        Type=String,\n";
  s << "        Category=Vertices;\n\n";
  s << "*CMD=DefineAttribute,\n";
  s << "        Name=Name,\n";
  s << "        Type=String,\n";
  s << "        Category=Vertices;\n\n";
  s << "*CMD=DefineAttribute,\n";
  s << "        Name=Address,\n";
  s << "        Type=String,\n";
  s << "        Category=Vertices;\n\n";

  s << "*CMD=DefineAttribute,\n";
  s << "        Name=Name,\n";
  s << "        Type=String,\n";
  s << "        Category=Edges;\n\n";

  s << "*CMD=SetKeyAttribute,\n";
  s << "        Category=Vertices,";
  s << "        Name=Internal;\n\n";
  dump_varnode_vertex(data,s);
  dump_op_vertex(data,s);
  dump_edges(data,s);
}

static void print_block_vertex(FlowBlock *bl,ostream &s)

{
  s << ' ' << dec << bl->sizeOut();
  s << ' ' << dec << bl->sizeIn();
  s << ' ' << dec << bl->getIndex();
  s << ' ' << hex << bl->getStart().getOffset();
  s << ' ' << bl->getStop().getOffset();
  s << endl;
}

static void print_block_edge(FlowBlock *bl,ostream &s)

{
  for(int4 i=0;i<bl->sizeIn();++i)
    s << dec << bl->getIn(i)->getIndex() << ' ' << bl->getIndex() << endl;
}

static void dump_block_vertex(const BlockGraph &graph,ostream &s,bool falsenode)

{
  s << "\n\n// Add Vertices\n";
  s << "*CMD=*COLUMNAR_INPUT,\n";
  s << "  Command=AddVertices,\n";
  s << "  Parsing=WhiteSpace,\n";
  s << "  Fields=({Name=SizeOut, Location=1},\n";
  s << "          {Name=SizeIn, Location=2},\n";
  s << "          {Name=Internal, Location=3},\n";
  s << "          {Name=Index, Location=4},\n";
  s << "          {Name=Start, Location=5},\n";
  s << "          {Name=Stop, Location=6});\n\n";

  if (falsenode)
    s << "-1 0 0 -1 0 0\n";
  for(int4 i=0;i<graph.getSize();++i)
    print_block_vertex(graph.getBlock(i),s);
  s << "*END_COLUMNS\n";
}

static void dump_block_edges(const BlockGraph &graph,ostream &s)

{
  s << "\n\n// Add Edges\n";
  s << "*CMD=*COLUMNAR_INPUT,\n";
  s << "  Command=AddEdges,\n";
  s << "  Parsing=WhiteSpace,\n";
  s << "  Fields=({Name=*FromKey, Location=1},\n";
  s << "          {Name=*ToKey, Location=2});\n\n";

  for(int4 i=0;i<graph.getSize();++i)
    print_block_edge(graph.getBlock(i),s);
  s << "*END_COLUMNS\n";
}

static void print_dom_edge(FlowBlock *bl,ostream &s,bool falsenode)

{
  FlowBlock *dom = bl->getImmedDom();

  if (dom != (FlowBlock *)0)
    s << dec << dom->getIndex() << ' ' << bl->getIndex() << endl;
  else if (falsenode)
    s << "-1 " << dec << bl->getIndex() << endl;
}

static void dump_dom_edges(const BlockGraph &graph,ostream &s,bool falsenode)

{
  s << "\n\n// Add Edges\n";
  s << "*CMD=*COLUMNAR_INPUT,\n";
  s << "  Command=AddEdges,\n";
  s << "  Parsing=WhiteSpace,\n";
  s << "  Fields=({Name=*FromKey, Location=1},\n";
  s << "          {Name=*ToKey, Location=2});\n\n";

  for(int4 i=0;i<graph.getSize();++i)
    print_dom_edge(graph.getBlock(i),s,falsenode);
  s << "*END_COLUMNS\n";
}

static void dump_block_attributes(ostream &s)

{
  s << "\n// Attributes\n";
  s << "*CMD=DefineAttribute,\n";
  s << "        Name=SizeOut,\n";
  s << "        Type=String,\n";
  s << "        Category=Vertices;\n\n";
  s << "*CMD=DefineAttribute,\n";
  s << "        Name=SizeIn,\n";
  s << "        Type=String,\n";
  s << "        Category=Vertices;\n\n";
  s << "*CMD=DefineAttribute,\n";
  s << "        Name=Internal,\n";
  s << "        Type=String,\n";
  s << "        Category=Vertices;\n\n";
  s << "*CMD=DefineAttribute,\n";
  s << "        Name=Index,\n";
  s << "        Type=String,\n";
  s << "        Category=Vertices;\n\n";
  s << "*CMD=DefineAttribute,\n";
  s << "        Name=Start,\n";
  s << "        Type=String,\n";
  s << "        Category=Vertices;\n\n";
  s << "*CMD=DefineAttribute,\n";
  s << "        Name=Stop,\n";
  s << "        Type=String,\n";
  s << "        Category=Vertices;\n\n";

  s << "*CMD=SetKeyAttribute,\n";
  s << "        Category=Vertices,";
  s << "        Name=Index;\n\n";
}

static void dump_block_properties(ostream &s)

{
  s << "\n// AutomaticArrangement\n";
  s << "  *CMD = AlterLocalPreferences, Name = AutomaticArrangement,\n";
  s << "  ~ReplaceAllParams = TRUE,\n";
  s << "  EnableAutomaticArrangement=true,\n";
  s << "  OnlyActOnVerticesWithoutCoordsIfOff=false,\n";
  s << "  DontUpdateMediumWithUserArrangement=false,\n";
  s << "  UserAddedArrangmentParams=({ServiceName=SimpleHierarchyFromSources,ServiceParams={~SkipPromptForParams=true}}),\n";
  s << "  SmallSize=50,\n";
  s << "  DontUpdateLargeWithUserArrangement=true,\n";
  s << "  NewVertexActionIfOff=ArrangeByMDS,\n";
  s << "  MediumSizeArrangement=SimpleHierarchyFromSources,\n";
  s << "  SmallSizeArrangement=SimpleHierarchyFromSources,\n";
  s << "  MediumSize=800,\n";
  s << "  LargeSizeArrangement=ArrangeInCircle,\n";
  s << "  DontUpdateSmallWithUserArrangement=false,\n";
  s << "  ActionSizeGainIfOff=1.0;\n";
  
  s << "\n// VertexColors\n";
  s << "  *CMD = AlterLocalPreferences, Name = VertexColors,\n";
  s << "  ~ReplaceAllParams = TRUE,\n";
  s << "  Mapping=({DisplayChoice=Red,AttributeValue=0},\n";
  s << "  {DisplayChoice=Blue,AttributeValue=1},\n";
  s << "  {DisplayChoice=Yellow,AttributeValue=2}),\n";
  s << "  ChoiceForValueNotCovered=Purple,\n";
  s << "  Extraction=CompleteValue,\n";
  s << "  ExtractionParams={},\n";
  s << "  AttributeName=SizeOut,\n";
  s << "  ChoiceForMissingValue=Purple,\n";
  s << "  CanOverride=true,\n";
  s << "  OverrideAttributeName=Color,\n";
  s << "  UsingRange=false;\n";

  s << "\n//     VertexIcons\n";
  s << "  *CMD = AlterLocalPreferences, Name = VertexIcons,\n";
  s << "  ~ReplaceAllParams = TRUE,\n";
  s << "  Mapping=({DisplayChoice=Square,AttributeValue=0}),\n";
  s << "  ChoiceForValueNotCovered=Circle,\n";
  s << "  Extraction=CompleteValue,\n";
  s << "  ExtractionParams={},\n";
  s << "  AttributeName=SizeIn,\n";
  s << "  ChoiceForMissingValue=Circle,\n";
  s << "  CanOverride=true,\n";
  s << "  OverrideAttributeName=Icon,\n";
  s << "  UsingRange=false;\n";

  s << "\n//     VertexLabels\n";
  s << "  *CMD = AlterLocalPreferences, Name = VertexLabels,\n";
  s << "  ~ReplaceAllParams = TRUE,\n";
  s << "  Center=({MaxLines=4,SqueezeLinesTogether=true,TreatBackSlashNAsNewLine=false,FontSize=10,Format=StandardFormat,IncludeBackground=false,BackgroundColor=Black,AttributeName=Start,UseSpecialFontName=false,SpecialColor=Black,SpecialFontName=SansSerif,UseSpecialColor=false,LabelAlignment=Center,MaxWidth=100}),\n";
  s << "  East=(),\n";
  s << "  SouthEast=(),\n";
  s << "  North=(),\n";
  s << "  West=(),\n";
  s << "  SouthWest=(),\n";
  s << "  NorthEast=(),\n";
  s << "  South=(),\n";
  s << "  NorthWest=();\n";
}

void dump_controlflow_graph(const string &name,const BlockGraph &graph,ostream &s)

{
  s << "*CMD=NewGraphWindow, WindowName=" << name << "-controlflow;\n";
  s << "*CMD=*NEXUS,Name=" << name << "-controlflow;\n";
  dump_block_properties(s);
  dump_block_attributes(s);
  dump_block_vertex(graph,s,false);
  dump_block_edges(graph,s);
}

void dump_dom_graph(const string &name,const BlockGraph &graph,ostream &s)

{
  int4 count = 0;

  for(int4 i=0;i<graph.getSize();++i)
    if (graph.getBlock(i)->getImmedDom() == (FlowBlock *)0)
      count += 1;
  bool falsenode = (count>1);
  s << "*CMD=NewGraphWindow, WindowName=" << name << "-dom;\n";
  s << "*CMD=*NEXUS,Name=" << name << "-dom;\n";
  dump_block_properties(s);
  dump_block_attributes(s);
  dump_block_vertex(graph,s,falsenode);
  dump_dom_edges(graph,s,falsenode);
}
