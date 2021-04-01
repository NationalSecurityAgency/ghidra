## ###
#  IP: GHIDRA
# 
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#  
#       http://www.apache.org/licenses/LICENSE-2.0
#  
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
##
#Given a function, find all strings used within all called funtions.
# @category: Strings

# Handles only functions, not subroutines, as of now.  Hopefully this will change later

import ghidra.app.script.GhidraScript
import ghidra.program.model.data.StringDataType as StringDataType
import exceptions

class Node:
    def __str__(self):
        raise NotImplementedError("Must sub-class")
    def indentedString(self, depth=0):
        raise NotImplementedError("")
    def __str__(self):
        return self.indentedString(depth=0)

class ReferenceNode(Node):
    def __init__(self, fromAddr, toAddr):
        self.fromAddr = fromAddr
        self.toAddr = toAddr
    def indentedString(self, depth=0):
        raise NotImplementedError("")

class StringNode(ReferenceNode):
    def __init__(self, fromAddr, toAddr, string):
        ReferenceNode.__init__(self, fromAddr, toAddr)
        self.string = string
    def __str__(self):
        return self.indentedString(depth=0)
    def indentedString(self, depth=0):
        string = "%s\n" % ( self.string)
        return string
    def hasString(self):
        return True

class FunctionNode(ReferenceNode):
    def __init__(self, fromAddr, toAddr):
        ReferenceNode.__init__(self, fromAddr, toAddr)
        self.fn = getFunctionContaining(toAddr)
        self.references = []
    def hasString(self):
        for r in self.references:
            if isinstance(r, StringNode) or r.hasString():
                return True
        return False
    def indentedString(self, depth=0):
        string = "%s()\n" % (self.fn.getName())
        for r in self.references:
            if r.hasString():
                string += "%s@%s - %s" % ("   " * (depth+1), r.fromAddr, r.indentedString(depth=depth+1))
        return string
    def getAddresses(self):
        return self.fn.getBody().getAddresses(True)
    def addReference(self, reference):
        rlist = []
        if not isinstance(reference, list):
            rlist.append(reference)
        for r in rlist:
            if not isinstance(r, ReferenceNode):
                raise ValueError("Must only add ReferenceNode type")
            else:
                self.references.append(r)
    def getName(self):
        if self.fn is not None:
            return self.fn.getName()
        else:
            return "fun_%s" % (self.toAddr)
    def process(self, processed=[]):
        if self.fn is None:
            return processed
        print "Processing %s -> %s" % (str(self.fromAddr), str(self.toAddr))
        if self.getName() in processed:
            return processed
        addresses = self.getAddresses()
        print str(type(addresses))
        while addresses.hasNext():
            #for a in addresses:
            a = addresses.next()
            insn = getInstructionAt(a)
            if insn is not None:
                refs = getReferences(insn)
                for r in refs:
                    self.addReference(r)
        
        processed.append(self.getName())
        for r in self.references:
            if isinstance(r, FunctionNode):
                processed = r.process(processed=processed)
        return processed
    
class FunctionNotFoundException(exceptions.Exception):
    pass   

def getStringAtAddr(addr):
    """Get string at an address, if present"""
    data = getDataAt(addr)
    if data is not None:
        dt = data.getDataType()
        if isinstance(dt, StringDataType):
            return str(data)
    return None

def getStringReferences(insn):
    """Get strings referenced in any/all operands of an instruction, if present"""
    numOperands = insn.getNumOperands()
    found = []
    for i in range(numOperands):
        opRefs = insn.getOperandReferences(i)
        for o in opRefs:
            if o.getReferenceType().isData():
                string = getStringAtAddr(o.getToAddress())
                if string is not None:
                    found.append( StringNode(insn.getMinAddress(), o.getToAddress(), string) )
    return found

def getFunctionReferences(insn):
    """Return a list of functions referenced in the given instruction"""
    numOperands = insn.getNumOperands()
    lst = []
    for i in range(numOperands):
        opRefs = insn.getOperandReferences(i)
        for o in opRefs:
            if o.getReferenceType().isCall():
                lst.append( FunctionNode(insn.getMinAddress(), o.getToAddress()) )
    return lst

def getReferences(insn):
    refs = []
    refs += getStringReferences(insn)
    refs += getFunctionReferences(insn)
    return refs

bigfunc = getFunctionContaining(currentAddress)
if bigfunc is None:
    print "Please place the cursor within a function!"
else:
    AddrSetView = bigfunc.getBody()
    func = FunctionNode(None, AddrSetView.getMinAddress())
    func.process()
    print str(func.indentedString())
    #findStrings(func)
    print "Done!"




