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
#include "typegrp_ghidra.hh"

Datatype *TypeFactoryGhidra::findById(const string &n,uint8 id,int4 sz)

{
  Datatype *ct = TypeFactory::findById(n,id,sz); // Try internal find
  if (ct != (Datatype *)0) return ct;

  Document *doc;
  try {
    doc = ((ArchitectureGhidra *)glb)->getType(n,id); // See if ghidra knows about type
  }
  catch(XmlError &err) {
    throw LowlevelError("XML error: "+err.explain);
  }
  if (doc == (Document *)0) return (Datatype *)0;
  ct = restoreXmlType(doc->getRoot()); // Parse ghidra's type
  delete doc;
  return ct;
}
