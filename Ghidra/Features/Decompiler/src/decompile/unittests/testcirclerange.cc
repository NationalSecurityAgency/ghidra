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
#include "architecture.hh"
#include "test.hh"

namespace ghidra {

class CircleRangeTestEnvironment {
  Architecture *g;
public:
  CircleRangeTestEnvironment(void);
  ~CircleRangeTestEnvironment(void);
  static void build(void);
};

static Architecture *glb;
static CircleRangeTestEnvironment theEnviron;

CircleRangeTestEnvironment::CircleRangeTestEnvironment(void)

{
  g = (Architecture *)0;
}

void CircleRangeTestEnvironment::build(void)

{
  if (theEnviron.g != (Architecture *)0) return;
  ArchitectureCapability *xmlCapability = ArchitectureCapability::getCapability("xml");
  istringstream s(
      "<binaryimage arch=\"x86:LE:64:default:gcc\"></binaryimage>"
  );
  DocumentStorage store;
  Document *doc = store.parseDocument(s);
  store.registerTag(doc->getRoot());

  theEnviron.g = xmlCapability->buildArchitecture("", "", &cout);
  theEnviron.g->init(store);

  glb = theEnviron.g;
}

CircleRangeTestEnvironment::~CircleRangeTestEnvironment(void)

{
  if (g != (Architecture *)0)
    delete g;
}

class CircleRangeTest {
  vector<uintb> elements;
  uintb mask;
  int4 bytes;
  bool getStartStopStep(uintb &start,uintb &stop,int4 &step);
public:
  CircleRangeTest(const CircleRange &range);
  void set_intersect(CircleRangeTest &op2);
  void set_union(CircleRangeTest &op2);
  void pushUnary(OpCode opcode,int4 outsize);
  void pullbackUnary(OpCode opcode,int4 insize);
  void pullbackBinary(OpCode opcode,int4 slot,uintb val);
  bool testEqual(bool valid,const CircleRange &range);
  static bool testIntersect(uintb start1,uintb stop1,uintb start2,uintb stop2,int4 step,int4 bytes);
  static bool testUnion(uintb start1,uintb stop1,uintb start2,uintb stop2,int4 step,int4 bytes);
  static bool testPullbackUnary(uintb start,uintb stop,int4 step,int4 bytes,OpCode opcode,int4 insize);
  static bool testPullbackBinary(uintb start,uintb stop,int4 step,int4 bytes,OpCode opcode,int4 slot,uintb val);
  static bool testPushUnary(uintb start,uintb stop,int4 step,int4 bytes,OpCode opcode,int4 outsize);
};

bool CircleRangeTest::testPullbackUnary(uintb start,uintb stop,int4 step,int4 bytes,OpCode opcode,int4 insize)

{
  CircleRange range(start,stop,bytes,step);
  CircleRangeTest testrange(range);
  bool valid = range.pullBackUnary(opcode, insize, bytes);
  testrange.pullbackUnary(opcode,insize);
  return testrange.testEqual(valid,range);
}

bool CircleRangeTest::testPullbackBinary(uintb start,uintb stop,int4 step,int4 bytes,OpCode opcode,int4 slot,uintb val)

{
  CircleRange range(start,stop,bytes,step);
  CircleRangeTest testrange(range);
  bool valid = range.pullBackBinary(opcode, val, slot, bytes, bytes);
  testrange.pullbackBinary(opcode, slot, val);
  return testrange.testEqual(valid,range);
}

bool CircleRangeTest::testPushUnary(uintb start,uintb stop,int4 step,int4 bytes,OpCode opcode,int4 outsize)

{
  CircleRange range(start,stop,bytes,step);
  CircleRange res;
  CircleRangeTest testrange(range);
  bool valid = res.pushForwardUnary(opcode, range, bytes, outsize);
  testrange.pushUnary(opcode,outsize);
  return testrange.testEqual(valid,res);
}

bool CircleRangeTest::testIntersect(uintb start1,uintb stop1,uintb start2,uintb stop2,int4 step,int4 bytes)

{
  CircleRange range1(start1,stop1,bytes,step);
  CircleRange range2(start2,stop2,bytes,step);
  CircleRangeTest testrange1(range1);
  CircleRangeTest testrange2(range2);

  int4 code = range1.intersect(range2);
  testrange1.set_intersect(testrange2);
  return testrange1.testEqual(code == 0, range1);
}

bool CircleRangeTest::testUnion(uintb start1,uintb stop1,uintb start2,uintb stop2,int4 step,int4 bytes)

{
  CircleRange range1(start1,stop1,bytes,step);
  CircleRange range2(start2,stop2,bytes,step);
  CircleRangeTest testrange1(range1);
  CircleRangeTest testrange2(range2);

  int4 code = range1.circleUnion(range2);
  testrange1.set_union(testrange2);
  return testrange1.testEqual(code == 0, range1);
}

CircleRangeTest::CircleRangeTest(const CircleRange &range)

{
  mask = range.getMask();
  if (!range.isEmpty()) {
    uintb start = range.getMin();
    do {
      elements.push_back(start);
    } while(range.getNext(start));
  }
  uintb temp = mask + 1;
  if (temp == 0) {
    bytes = 8;
  }
  else {
    bytes = -1;
    while(temp != 0) {
      temp >>= 1;
      bytes += 1;
    }
    bytes /= 8;
  }
}

bool CircleRangeTest::testEqual(bool valid,const CircleRange &range)

{
  if (elements.empty()) {
    return range.isEmpty();
  }
  else if (range.isEmpty()) {
    return false;
  }
  uintb start,stop;
  int4 step;
  bool testvalid = getStartStopStep(start,stop,step);
  if (testvalid != valid) return false;
  if (!valid) return true;
  if (start != range.getMin()) return false;
  if (stop != range.getEnd()) return false;
  if (step != range.getStep()) return false;
  return true;
}

void CircleRangeTest::set_intersect(CircleRangeTest &op2)

{
  vector<uintb> res(elements.size() + op2.elements.size());
  sort(elements.begin(),elements.end());
  sort(op2.elements.begin(),op2.elements.end());
  vector<uintb>::iterator iter;
  iter = set_intersection(elements.begin(),elements.end(),op2.elements.begin(),op2.elements.end(),res.begin());
  elements.assign(res.begin(),iter);
}

void CircleRangeTest::set_union(CircleRangeTest &op2)

{
  vector<uintb> res(elements.size() + op2.elements.size());
  sort(elements.begin(),elements.end());
  sort(op2.elements.begin(),op2.elements.end());
  vector<uintb>::iterator iter;
  iter = std::set_union(elements.begin(),elements.end(),op2.elements.begin(),op2.elements.end(),res.begin());
  elements.assign(res.begin(),iter);
}

void CircleRangeTest::pushUnary(OpCode opcode,int4 outsize)

{
  CircleRangeTestEnvironment::build();
  OpBehavior *behave = glb->inst[opcode]->getBehavior();
  for(int4 i=0;i<elements.size();++i) {
    elements[i] = behave->evaluateUnary(outsize, bytes, elements[i]);
  }
  if (outsize != bytes) {
    bytes = outsize;
    mask = calc_mask(outsize);
  }
}

void CircleRangeTest::pullbackUnary(OpCode opcode,int4 insize)

{
  CircleRangeTestEnvironment::build();
  OpBehavior *behave = glb->inst[opcode]->getBehavior();
  vector<uintb> res;
  for(int4 i=0;i<elements.size();++i) {
    try {
      res.push_back(behave->recoverInputUnary(bytes, elements[i], insize));
    } catch(EvaluationError &err) {
      // output is not in range
    }
  }
  elements = res;
  if (insize != bytes) {
    bytes = insize;
    mask = calc_mask(insize);
  }
}

void CircleRangeTest::pullbackBinary(OpCode opcode,int4 slot,uintb val)

{
  CircleRangeTestEnvironment::build();
  OpBehavior *behave = glb->inst[opcode]->getBehavior();
  vector<uintb> res;
  for(int4 i=0;i<elements.size();++i) {
    try {
      res.push_back(behave->recoverInputBinary(slot, bytes, elements[i], bytes, val));
    } catch(EvaluationError &err) {
      // output is not in range
    }
  }
  elements = res;
}

bool CircleRangeTest::getStartStopStep(uintb &start,uintb &stop,int4 &step)

{
  if (elements.empty()) {
    start = 0;
    stop = 0;
    step = 1;
    return true;
  }
  sort(elements.begin(),elements.end());
  int4 bigpos = -1;
  uintb biggest1 = 0;
  uintb biggest2 = 0;

  if (elements.back() > mask) return false;

  for(int4 i=1;i<elements.size();++i) {
    uintb diff = elements[i] - elements[i-1];
    if (diff >= biggest1) {
      if (diff > biggest1) {
	biggest2 = biggest1;
	biggest1 = diff;
	bigpos = i;
      }
    }
    else if (diff > biggest2)
      biggest2 = diff;
  }

  if (biggest1 == 0) return false;
  if (biggest2 == 0) {
    step = biggest1;
    start = elements[0];
    stop = (elements.back() + step) & mask;
    return true;
  }
  int4 count1 = 0;
  int4 count2 = 0;
  int4 count3 = 0;
  for(int4 i=1;i<elements.size();++i) {
    uintb diff = elements[i] - elements[i-1];
    if (diff == biggest1)
      count1 += 1;
    else if (diff == biggest2)
      count2 += 1;
    else
      count3 += 1;
  }
  if (count3 > 0) return false;
  if (count1 > 1) return false;
  step = biggest2;
  uintb tmp = elements.back() + step;
  if (tmp <= mask) return false;
  tmp -= (mask + 1);
  if (tmp != elements[0]) return false;
  start = elements[bigpos];
  stop = elements[bigpos-1] + step;
  return true;
}

TEST(circlerange_intersect1) {
  ASSERT(CircleRangeTest::testIntersect(1,20,  10, 30,   1, 4));
}

TEST(circlerange_intersect2) {
  ASSERT(CircleRangeTest::testIntersect(200,10,   250, 5,  1,1));
}

TEST(circlerange_intersect3) {
  ASSERT(CircleRangeTest::testIntersect(1,250,   240, 5,   1,1));
}

TEST(circlerange_intersect4) {
  ASSERT(CircleRangeTest::testIntersect(4,100,  248, 52,   4,1));
}

TEST(circlerange_intersect5) {
  ASSERT(CircleRangeTest::testIntersect(0x100000, 0x1000fe, 0xfffffffffffffff0, 0xfffffffffffffffe, 2, 8));
}

TEST(circlerange_intersect6) {
  ASSERT(CircleRangeTest::testIntersect(0x100, 0x110, 0x110, 0x130, 4, 2));
}

TEST(circlerange_intersect7) {
  ASSERT(CircleRangeTest::testIntersect(0xffe0, 0x20, 0, 0x20, 2, 2));
}

TEST(circlerange_intersect8) {
  ASSERT(CircleRangeTest::testIntersect(0x80, 0x8, 0xd0, 0x80, 1, 1));
}

TEST(circlerange_union1) {
  ASSERT(CircleRangeTest::testUnion(1,20,  10, 30,   1, 4));
}

TEST(circlerange_union2) {
  ASSERT(CircleRangeTest::testUnion(200,10,   250, 5,  1,1));
}

TEST(circlerange_union3) {
  ASSERT(CircleRangeTest::testUnion(1,250,   240, 5,   1,1));
}

TEST(circlerange_union4) {
  ASSERT(CircleRangeTest::testUnion(4,100,  248, 52,   4,1));
}

TEST(circlerange_union5) {
  ASSERT(CircleRangeTest::testUnion(0x100000, 0x1000fe, 0xfffffffffffffff0, 0xfffffffffffffffe, 2, 8));
}

TEST(circlerange_union6) {
  ASSERT(CircleRangeTest::testUnion(0x100, 0x110, 0x110, 0x130, 4, 2));
}

TEST(circlerange_union7) {
  ASSERT(CircleRangeTest::testUnion(0xffe0, 0x20, 0, 0x20, 2, 2));
}

TEST(circlerange_union8) {
  ASSERT(CircleRangeTest::testUnion(0x80, 0x8, 0xd0, 0x80, 1, 1));
}

TEST(circlerange_pullbacknegate1) {
  ASSERT(CircleRangeTest::testPullbackUnary(1, 20, 1, 4, CPUI_INT_NEGATE,4));
}

TEST(circlerange_pullbacknegate2) {
  ASSERT(CircleRangeTest::testPullbackUnary(0xf0, 0x10, 1, 1, CPUI_INT_NEGATE,1));
}

TEST(circlerange_pullbacknegate3) {
  ASSERT(CircleRangeTest::testPullbackUnary(0x10, 0x30, 4, 4, CPUI_INT_NEGATE,4));
}

TEST(circlerange_pullbacknegate4) {
  ASSERT(CircleRangeTest::testPullbackUnary(0xfff0, 0x0, 4, 2, CPUI_INT_NEGATE,2));
}

TEST(circlerange_pullbacknegate5) {
  ASSERT(CircleRangeTest::testPullbackUnary(0xd1, 0x11, 4, 1, CPUI_INT_NEGATE,1));
}

TEST(circlerange_pullbacknegate6) {
  ASSERT(CircleRangeTest::testPullbackUnary(0, 0x30, 4, 1, CPUI_INT_NEGATE,1));
}

TEST(circlerange_pullbackminus1) {
  ASSERT(CircleRangeTest::testPullbackUnary(1, 20, 1, 4, CPUI_INT_2COMP,4));
}

TEST(circlerange_pullbackminus2) {
  ASSERT(CircleRangeTest::testPullbackUnary(0xf0, 0x10, 1, 1, CPUI_INT_2COMP,1));
}

TEST(circlerange_pullbackminus3) {
  ASSERT(CircleRangeTest::testPullbackUnary(0x10, 0x30, 4, 4, CPUI_INT_2COMP,4));
}

TEST(circlerange_pullbackminus4) {
  ASSERT(CircleRangeTest::testPullbackUnary(0xfff0, 0x0, 4, 2, CPUI_INT_2COMP,2));
}

TEST(circlerange_pullbackminus5) {
  ASSERT(CircleRangeTest::testPullbackUnary(0xd1, 0x11, 4, 1, CPUI_INT_2COMP,1));
}

TEST(circlerange_pullbackminus6) {
  ASSERT(CircleRangeTest::testPullbackUnary(0, 0x30, 4, 1, CPUI_INT_2COMP,1));
}

TEST(circlerange_pullbackzext1) {
  ASSERT(CircleRangeTest::testPullbackUnary(1, 20, 1, 4, CPUI_INT_ZEXT,2));
}

TEST(circlerange_pullbackzext2) {
  ASSERT(CircleRangeTest::testPullbackUnary(0xfff0, 0xff10, 1, 2, CPUI_INT_ZEXT,1));
}

TEST(circlerange_pullbackzext3) {
  ASSERT(CircleRangeTest::testPullbackUnary(0x10, 0x30, 4, 4, CPUI_INT_ZEXT,1));
}

TEST(circlerange_pullbackzext4) {
  ASSERT(CircleRangeTest::testPullbackUnary(0xfff0, 0x0, 4, 2, CPUI_INT_ZEXT,1));
}

TEST(circlerange_pullbackzext5) {
  ASSERT(CircleRangeTest::testPullbackUnary(0xffd1, 0x11, 4, 2, CPUI_INT_ZEXT,1));
}

TEST(circlerange_pullbackzext6) {
  ASSERT(CircleRangeTest::testPullbackUnary(0, 0x30, 4, 4, CPUI_INT_ZEXT,2));
}

TEST(circlerange_pullbacksext1) {
  ASSERT(CircleRangeTest::testPullbackUnary(1, 20, 1, 4, CPUI_INT_SEXT,2));
}

TEST(circlerange_pullbacksext2) {
  ASSERT(CircleRangeTest::testPullbackUnary(0xfff0, 0x10, 1, 2, CPUI_INT_SEXT,1));
}

TEST(circlerange_pullbacksext3) {
  ASSERT(CircleRangeTest::testPullbackUnary(0x10, 0x30, 4, 4, CPUI_INT_SEXT,2));
}

TEST(circlerange_pullbacksext4) {
  ASSERT(CircleRangeTest::testPullbackUnary(0xfff0, 0x0, 4, 2, CPUI_INT_SEXT,1));
}

TEST(circlerange_pullbacksext5) {
  ASSERT(CircleRangeTest::testPullbackUnary(0xffd1, 0x11, 4, 2, CPUI_INT_SEXT,1));
}

TEST(circlerange_pullbacksext6) {
  ASSERT(CircleRangeTest::testPullbackUnary(0, 0x30, 4, 2, CPUI_INT_SEXT,1));
}

TEST(circlerange_pullbackadd1) {
  ASSERT(CircleRangeTest::testPullbackBinary(1, 20, 1, 4, CPUI_INT_ADD, 0, 0xfffffffd));
}

TEST(circlerange_pullbackadd2) {
  ASSERT(CircleRangeTest::testPullbackBinary(0xf0, 0x10, 1, 1, CPUI_INT_ADD, 0, 0xfffffffd));
}

TEST(circlerange_pullbackadd3) {
  ASSERT(CircleRangeTest::testPullbackBinary(0x10, 0x30, 4, 4, CPUI_INT_ADD, 0, 0xfffffffd));
}

TEST(circlerange_pullbackadd4) {
  ASSERT(CircleRangeTest::testPullbackBinary(0xfff0, 0x0, 4, 2, CPUI_INT_ADD, 0, 0xfffffffd));
}

TEST(circlerange_pullbackadd5) {
  ASSERT(CircleRangeTest::testPullbackBinary(0xd1, 0x11, 4, 1, CPUI_INT_ADD, 0, 0xfffffffd));
}

TEST(circlerange_pullbackadd6) {
  ASSERT(CircleRangeTest::testPullbackBinary(0, 0x30, 4, 1, CPUI_INT_ADD, 0, 0xfffffffd));
}

TEST(circlerange_pullbacksub1) {
  ASSERT(CircleRangeTest::testPullbackBinary(1, 20, 1, 4, CPUI_INT_SUB, 0, 0xfffffffd));
}

TEST(circlerange_pullbacksub2) {
  ASSERT(CircleRangeTest::testPullbackBinary(0xf0, 0x10, 1, 1, CPUI_INT_SUB, 0, 0xfffffffd));
}

TEST(circlerange_pullbacksub3) {
  ASSERT(CircleRangeTest::testPullbackBinary(0x10, 0x30, 4, 4, CPUI_INT_SUB, 0, 0xfffffffd));
}

TEST(circlerange_pullbacksub4) {
  ASSERT(CircleRangeTest::testPullbackBinary(0xfff0, 0x0, 4, 2, CPUI_INT_SUB, 0, 0xfffffffd));
}

TEST(circlerange_pullbacksub5) {
  ASSERT(CircleRangeTest::testPullbackBinary(0xd1, 0x11, 4, 1, CPUI_INT_SUB, 0, 0xfffffffd));
}

TEST(circlerange_pullbacksub6) {
  ASSERT(CircleRangeTest::testPullbackBinary(0, 0x30, 4, 1, CPUI_INT_SUB, 0, 0xfffffffd));
}

TEST(circlerange_pullbackright1) {
  CircleRange range(0x01, 0x0f, 2, 1);
  bool valid = range.pullBackBinary(CPUI_INT_RIGHT, 8, 0, 2, 2);
  ASSERT(valid);
  ASSERT_EQUALS(range.getMin(),0x100);
  ASSERT_EQUALS(range.getEnd(),0xf00);
}

TEST(circlerange_pullbackright2) {
  CircleRange range(0xf0,0x10,2,1);
  bool valid = range.pullBackBinary(CPUI_INT_RIGHT, 8, 0, 2, 2);
  ASSERT(valid);
  ASSERT_EQUALS(range.getMin(),0xf000);
  ASSERT_EQUALS(range.getEnd(),0x1000);
}

TEST(circlerange_pullbackright3) {
  CircleRange range(0xf0,0x10,1,1);
  bool valid = range.pullBackBinary(CPUI_INT_RIGHT, 1, 0, 1, 1);
  ASSERT(valid);
  ASSERT_EQUALS(0,range.getMin());
  ASSERT_EQUALS(0x20,range.getEnd());
}

TEST(circlerange_pullbackright4) {
  CircleRange range(0x01, 0x0f, 2, 2);
  bool valid = range.pullBackBinary(CPUI_INT_RIGHT, 8, 0, 2, 2);
  ASSERT(!valid);
}

TEST(circlerange_pullbacksright1) {
  CircleRange range(0x01, 0x0f, 2, 1);
  bool valid = range.pullBackBinary(CPUI_INT_SRIGHT, 8, 0, 2, 2);
  ASSERT(valid);
  ASSERT_EQUALS(range.getMin(),0x100);
  ASSERT_EQUALS(range.getEnd(),0xf00);
}

TEST(circlerange_pullbacksright2) {
  CircleRange range(0xf0,0x10,1,1);
  bool valid = range.pullBackBinary(CPUI_INT_SRIGHT, 2, 0, 1, 1);
  ASSERT(valid);
  ASSERT_EQUALS(range.getMin(),0xc0);
  ASSERT_EQUALS(range.getEnd(),0x40);
}

TEST(circlerange_pullbacksright3) {
  CircleRange range(0x10,0x30,1,1);
  bool valid = range.pullBackBinary(CPUI_INT_SRIGHT, 2, 0, 1, 1);
  ASSERT(valid);
  ASSERT_EQUALS(range.getMin(),0x40);
  ASSERT_EQUALS(range.getEnd(),0x80);
}

TEST(circlerange_pullbacksright4) {
  CircleRange range(0x01, 0x0f, 2, 2);
  bool valid = range.pullBackBinary(CPUI_INT_SRIGHT, 8, 0, 2, 2);
  ASSERT(!valid);
}

TEST(circlerange_pullbackequal1) {
  CircleRange range(true);
  bool valid = range.pullBackBinary(CPUI_INT_EQUAL, 0x1234, 0, 4, 1);
  ASSERT(valid);
  ASSERT_EQUALS(range.getMin(), 0x1234);
  ASSERT_EQUALS(range.getEnd(), 0x1235);
}

TEST(circlerange_pullbackequal2) {
  CircleRange range(false);
  bool valid = range.pullBackBinary(CPUI_INT_EQUAL, 0x1234, 0, 2, 1);
  ASSERT(valid);
  ASSERT_EQUALS(range.getMin(), 0x1235);
  ASSERT_EQUALS(range.getEnd(), 0x1234);
}

TEST(circlerange_pullbacknotequal1) {
  CircleRange range(false);
  bool valid = range.pullBackBinary(CPUI_INT_NOTEQUAL, 0x1234, 0, 4, 1);
  ASSERT(valid);
  ASSERT_EQUALS(range.getMin(), 0x1234);
  ASSERT_EQUALS(range.getEnd(), 0x1235);
}

TEST(circlerange_pullbacknotequal2) {
  CircleRange range(true);
  bool valid = range.pullBackBinary(CPUI_INT_NOTEQUAL, 0x1234, 0, 2, 1);
  ASSERT(valid);
  ASSERT_EQUALS(range.getMin(), 0x1235);
  ASSERT_EQUALS(range.getEnd(), 0x1234);
}

TEST(circlerange_pullbackcarry1) {
  CircleRange range(true);
  bool valid = range.pullBackBinary(CPUI_INT_CARRY, 0x1234, 0, 2, 1);
  ASSERT(valid);
  ASSERT_EQUALS(range.getMin(), 0xedcc);
  ASSERT_EQUALS(range.getEnd(), 0);
}

TEST(circlerange_pullbackcarry2) {
  CircleRange range(false);
  bool valid = range.pullBackBinary(CPUI_INT_CARRY, 0x1234, 0, 2, 1);
  ASSERT(valid);
  ASSERT_EQUALS(range.getMin(), 0);
  ASSERT_EQUALS(range.getEnd(), 0xedcc);
}

TEST(circlerange_pullbackless1) {
  CircleRange range(false);
  bool valid = range.pullBackBinary(CPUI_INT_LESS, 0x1234, 0, 4, 1);
  ASSERT(valid);
  ASSERT_EQUALS(range.getMin(), 0x1234);
  ASSERT_EQUALS(range.getEnd(), 0);
}

TEST(circlerange_pullbackless2) {
  CircleRange range(true);
  bool valid = range.pullBackBinary(CPUI_INT_LESS, 0x1234, 0, 2, 1);
  ASSERT(valid);
  ASSERT_EQUALS(range.getMin(), 0);
  ASSERT_EQUALS(range.getEnd(), 0x1234);
}

TEST(circlerange_pullbacklessequal1) {
  CircleRange range(false);
  bool valid = range.pullBackBinary(CPUI_INT_LESSEQUAL, 0x1234, 0, 4, 1);
  ASSERT(valid);
  ASSERT_EQUALS(range.getMin(), 0x1235);
  ASSERT_EQUALS(range.getEnd(), 0);
}

TEST(circlerange_pullbacklessequal2) {
  CircleRange range(true);
  bool valid = range.pullBackBinary(CPUI_INT_LESSEQUAL, 0x1234, 0, 2, 1);
  ASSERT(valid);
  ASSERT_EQUALS(range.getMin(), 0);
  ASSERT_EQUALS(range.getEnd(), 0x1235);
}

TEST(circlerange_pullbacksless1) {
  CircleRange range(false);
  bool valid = range.pullBackBinary(CPUI_INT_SLESS, 0x1234, 0, 4, 1);
  ASSERT(valid);
  ASSERT_EQUALS(range.getMin(), 0x1234);
  ASSERT_EQUALS(range.getEnd(), 0x80000000);
}

TEST(circlerange_pullbacksless2) {
  CircleRange range(true);
  bool valid = range.pullBackBinary(CPUI_INT_SLESS, 0x1234, 0, 2, 1);
  ASSERT(valid);
  ASSERT_EQUALS(range.getMin(), 0x8000);
  ASSERT_EQUALS(range.getEnd(), 0x1234);
}

TEST(circlerange_pullbackslessequal1) {
  CircleRange range(false);
  bool valid = range.pullBackBinary(CPUI_INT_SLESSEQUAL, 0x1234, 0, 4, 1);
  ASSERT(valid);
  ASSERT_EQUALS(range.getMin(), 0x1235);
  ASSERT_EQUALS(range.getEnd(), 0x80000000);
}

TEST(circlerange_pullbackslessequal2) {
  CircleRange range(true);
  bool valid = range.pullBackBinary(CPUI_INT_SLESSEQUAL, 0x1234, 0, 2, 1);
  ASSERT(valid);
  ASSERT_EQUALS(range.getMin(), 0x8000);
  ASSERT_EQUALS(range.getEnd(), 0x1235);
}

TEST(circlerange_pushnegate1) {
  ASSERT(CircleRangeTest::testPushUnary(1, 20, 1, 4, CPUI_INT_NEGATE,4));
}

TEST(circlerange_pushnegate2) {
  ASSERT(CircleRangeTest::testPushUnary(0xf0, 0x10, 1, 1, CPUI_INT_NEGATE,1));
}

TEST(circlerange_pushnegate3) {
  ASSERT(CircleRangeTest::testPushUnary(0x10, 0x30, 4, 4, CPUI_INT_NEGATE,4));
}

TEST(circlerange_pushnegate4) {
  ASSERT(CircleRangeTest::testPushUnary(0xfff0, 0x0, 4, 2, CPUI_INT_NEGATE,2));
}

TEST(circlerange_pushnegate5) {
  ASSERT(CircleRangeTest::testPushUnary(0xd1, 0x11, 4, 1, CPUI_INT_NEGATE,1));
}

TEST(circlerange_pushnegate6) {
  ASSERT(CircleRangeTest::testPushUnary(0, 0x30, 4, 1, CPUI_INT_NEGATE,1));
}

TEST(circlerange_pushminus1) {
  ASSERT(CircleRangeTest::testPushUnary(1, 20, 1, 4, CPUI_INT_2COMP,4));
}

TEST(circlerange_pushminus2) {
  ASSERT(CircleRangeTest::testPushUnary(0xf0, 0x10, 1, 1, CPUI_INT_2COMP,1));
}

TEST(circlerange_pushminus3) {
  ASSERT(CircleRangeTest::testPushUnary(0x10, 0x30, 4, 4, CPUI_INT_2COMP,4));
}

TEST(circlerange_pushminus4) {
  ASSERT(CircleRangeTest::testPushUnary(0xfff0, 0x0, 4, 2, CPUI_INT_2COMP,2));
}

TEST(circlerange_pushminus5) {
  ASSERT(CircleRangeTest::testPushUnary(0xd1, 0x11, 4, 1, CPUI_INT_2COMP,1));
}

TEST(circlerange_pushminus6) {
  ASSERT(CircleRangeTest::testPushUnary(0, 0x30, 4, 1, CPUI_INT_2COMP,1));
}

TEST(circlerange_pushzext1) {
  ASSERT(CircleRangeTest::testPushUnary(1, 20, 1, 2, CPUI_INT_ZEXT,4));
}

TEST(circlerange_pushzext2) {
  ASSERT(CircleRangeTest::testPushUnary(0xfff0, 0xff10, 1, 2, CPUI_INT_ZEXT,4));
}

TEST(circlerange_pushzext3) {
  ASSERT(CircleRangeTest::testPushUnary(0x10, 0x30, 4, 2, CPUI_INT_ZEXT,4));
}

TEST(circlerange_pushzext4) {
  ASSERT(CircleRangeTest::testPushUnary(0xfff0, 0x0, 4, 2, CPUI_INT_ZEXT,4));
}

TEST(circlerange_pushzext5) {
  ASSERT(CircleRangeTest::testPushUnary(0xffd1, 0xfff1, 4, 2, CPUI_INT_ZEXT,4));
}

TEST(circlerange_pushzext6) {
  ASSERT(CircleRangeTest::testPushUnary(0, 0x30, 4, 1, CPUI_INT_ZEXT,2));
}

TEST(circlerange_pushzext7) {
  ASSERT(CircleRangeTest::testPushUnary(0,0,4,1, CPUI_INT_ZEXT, 2));
}

TEST(circlerange_pushsext1) {
  ASSERT(CircleRangeTest::testPushUnary(1, 20, 1, 2, CPUI_INT_SEXT,4));
}

TEST(circlerange_pushsext2) {
  ASSERT(CircleRangeTest::testPushUnary(0xfff0, 0xff10, 1, 2, CPUI_INT_SEXT,4));
}

TEST(circlerange_pushsext3) {
  ASSERT(CircleRangeTest::testPushUnary(0x10, 0x30, 4, 2, CPUI_INT_SEXT,4));
}

TEST(circlerange_pushsext4) {
  ASSERT(CircleRangeTest::testPushUnary(0xfff0, 0x0, 4, 2, CPUI_INT_SEXT,4));
}

TEST(circlerange_pushsext5) {
  ASSERT(CircleRangeTest::testPushUnary(0xffd1, 0xfff1, 4, 2, CPUI_INT_SEXT,4));
}

TEST(circlerange_pushsext6) {
  ASSERT(CircleRangeTest::testPushUnary(0, 0x30, 4, 1, CPUI_INT_SEXT,2));
}

TEST(circlerange_pushsext7) {
  ASSERT(CircleRangeTest::testPushUnary(0,0,4,1, CPUI_INT_SEXT, 2));
}

} // End namespace ghidra
