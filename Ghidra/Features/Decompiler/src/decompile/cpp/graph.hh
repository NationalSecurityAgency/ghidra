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
#ifndef __GRAPH_HH__
#define __GRAPH_HH__

#include "funcdata.hh"

namespace ghidra {

extern void dump_dataflow_graph(Funcdata &data,ostream &s);
extern void dump_controlflow_graph(const string &name,const BlockGraph &graph,ostream &s);
extern void dump_dom_graph(const string &name,const BlockGraph &graph,ostream &s);

} // End namespace ghidra
#endif
