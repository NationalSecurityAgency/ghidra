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
#include "cpool_ghidra.hh"

namespace ghidra {

ConstantPoolGhidra::ConstantPoolGhidra(ArchitectureGhidra *g)

{
  ghidra = g;
}

CPoolRecord *ConstantPoolGhidra::createRecord(const vector<uintb> &refs)

{
  throw LowlevelError("Cannot access constant pool with this method");
}

const CPoolRecord *ConstantPoolGhidra::getRecord(const vector<uintb> &refs) const

{
  const CPoolRecord *rec = cache.getRecord(refs);
  if (rec == (const CPoolRecord *)0) {
    bool success;
    PackedDecode decoder(ghidra);
    try {
      success = ghidra->getCPoolRef(refs,decoder);
    }
    catch(JavaError &err) {
      throw LowlevelError("Error fetching constant pool record: " + err.explain);
    }
    catch(DecoderError &err) {
      throw LowlevelError("Error in constant pool record encoding: "+err.explain);
    }
    if (!success) {
      ostringstream s;
      s << "Could not retrieve constant pool record for reference: 0x" << refs[0];
      throw LowlevelError(s.str());
    }
    rec = cache.decodeRecord(refs,decoder,*ghidra->types);
  }
  return rec;
}

void ConstantPoolGhidra::encode(Encoder &encoder) const

{
  throw LowlevelError("Cannot access constant pool with this method");
}

void ConstantPoolGhidra::decode(Decoder &decoder,TypeFactory &typegrp)

{
  throw LowlevelError("Cannot access constant pool with this method");
}

} // End namespace ghidra
