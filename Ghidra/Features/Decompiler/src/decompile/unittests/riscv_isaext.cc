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
/**
 * @brief Verify that at least one user pcode operation is defined for each ratified
 * RISCV instruction set extension included as mandadatory or optional
 * in the default profile - e..g., rva23
 */
#include "architecture.hh"
#include "grammar.hh"
#include "test.hh"
#include <iostream>

namespace ghidra {

static Architecture *glb;

class RiscvPcodeTestEnvironment {
  Architecture *g;
public:
  RiscvPcodeTestEnvironment(void);
  ~RiscvPcodeTestEnvironment(void);
  static void build(void);
};

static RiscvPcodeTestEnvironment theEnviron;

RiscvPcodeTestEnvironment::RiscvPcodeTestEnvironment(void)

{
  g = (Architecture *)0;
}

void RiscvPcodeTestEnvironment::build(void)

{
  if (theEnviron.g != (Architecture *)0) return;
  ArchitectureCapability *xmlCapability = ArchitectureCapability::getCapability("xml");
  istringstream s(
      "<binaryimage arch=\"RISCV:LE:64:RV64GC\"></binaryimage>"
  );
  DocumentStorage store;
  Document *doc = store.parseDocument(s);
  store.registerTag(doc->getRoot());

  theEnviron.g = xmlCapability->buildArchitecture("", "", &cout);
  theEnviron.g->init(store);

  glb = theEnviron.g;
}

RiscvPcodeTestEnvironment::~RiscvPcodeTestEnvironment(void)

{
  if (g != (Architecture *)0)
    delete g;
}

TEST(riscvuserpcode) {
  RiscvPcodeTestEnvironment::build();
  // verify that we have a sane number of user ops
  ASSERT(glb->inst.size() >= 70);
  // verify that two RISCV vector userpcode ops are known
  ASSERT(glb->userops.getOp("vsetvli")->getName() == "vsetvli");
  ASSERT(glb->userops.getOp("vsetivli")->getName() == "vsetivli");
  // verify that a nonexistent userpcode returns null
  ASSERT(glb->userops.getOp("vsetivliXXX") == nullptr);
  // fmv_x_h is defined in riscv.zfh.sinc for half-precision floating point
  ASSERT(glb->userops.getOp("fmv_x_h")->getName() == "fmv_x_h");
  // vandn_vv is defined in riscv.zvbb.sinc for vector bit manipulation
  ASSERT(glb->userops.getOp("vandn_vv")->getName() == "vandn_vv");
  // vaesdf_vv is defined in riscv.zvkng.sinc for NIST vector crypto
  ASSERT(glb->userops.getOp("vaesdf_vv")->getName() == "vaesdf_vv");
  // vsm3c_vi is defined in riscv..sinc for ShangMi vector crypto
  ASSERT(glb->userops.getOp("vsm3c_vi")->getName() == "vsm3c_vi");
}

} // End namespace ghidra
