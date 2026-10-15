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
/// \file valuedomain.hh
/// \brief Conservative evaluation of request-local LOAD value domains
#ifndef __VALUEDOMAIN_HH__
#define __VALUEDOMAIN_HH__
#include "rangeutil.hh"
namespace ghidra {
class Funcdata;
class Varnode;
class PcodeOp;
class ValueDomainAnalysis {
public:
  static bool getRange(Funcdata *fd,Varnode *value,PcodeOp *use,CircleRange &range);
  static bool preservesGuard(Funcdata *fd,PcodeOp *branch,PcodeOp *use);
};
}
#endif
