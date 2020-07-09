#!/usr/bin/env python2
## -*- coding: utf-8 -*-

import sys
import triton
import pintool

taintedIns = 0x400767 
target     = 0x5  
taintSrcIns= 0x40074a

Triton = pintool.getTritonContext()
"""
def exploit_mmap(insn, op):
    regId   = Triton.getSymbolicRegisterId(op)
    regExpr = Triton.unrollAst(Triton.getAstFromId(regId))
    ast = Triton.getAstContext()
    exploitExpr = ast.equal(regExpr, ast.bv(target, triton.CPUSIZE.QWORD_BIT))

    print 'Getting model for %s -> equal 0x%x' % (insn, target)
    model = Triton.getModel(exploitExpr)
    for k, v in model.iteritems():
        print '%s (%s)' % (v, Triton.getSymbolicVariableFromId(k).getComment())
"""
a=0
def read_hook(tid):
    global a
    print("read_hook")
    print(hex(a))    
    for i in range(4):
        c = pintool.getCurrentMemoryValue(a+i)
        print(str(i)+" : "+str(hex(c)))
def hook(insn):
    global a
    if insn.getAddress() == 0x400740:
        for op in insn.getOperands():
            
            if op.getType() == triton.OPERAND.REG:
               
                addr = pintool.getCurrentRegisterValue(op)
                print(hex(addr))
                a=addr
                print("a:"+str(hex(a)))
                for i in range(4):
                    c = pintool.getCurrentMemoryValue(a+i)
                    print(str(i)+" : "+str(hex(c)))
    if insn.getAddress() == 0x40074a:
        print(hex(a))    
        for i in range(4):
            c = pintool.getCurrentMemoryValue(a+i)
            print(str(i)+" : "+str(hex(c)))
        
    if insn.getAddress() == 0x40074a:
        for op in insn.getOperands():
            
            if op.getType() == triton.OPERAND.MEM:
               
                addr = op.getAddress()
                print(hex(addr))
                
                c = pintool.getCurrentMemoryValue(addr)
                print(str(hex(c)))
"""
                Triton.setConcreteMemoryValue(addr, c)
                Triton.convertMemoryToSymbolicVariable(
                        triton.MemoryAccess(addr,triton.CPUSIZE.BYTE)
                    ).setComment('taintedByte '+str(hex(addr))+' : '+str(c))
           
                print('Symbolized taintedByte '+str(hex(addr))+' : '+str(c))

    if insn.getAddress() == taintedIns:
        for op in insn.getOperands():
            if op.getType() == triton.OPERAND.REG:
                print 'Found Target Ins \'%s\'' % (insn)
                exploit_mmap(insn, op)    
                return
"""
def main():
    Triton.setArchitecture(triton.ARCH.X86_64)
    Triton.enableMode(triton.MODE.ALIGNED_MEMORY, True)

    pintool.startAnalysisFromSymbol('main')

    pintool.insertCall(hook, pintool.INSERT_POINT.AFTER)
    pintool.insertCall(read_hook,pintool.INSERT_POINT.ROUTINE_EXIT,'read')
    #pintool.insertCall(hook_mmap, pintool.INSERT_POINT.AFTER)

    pintool.runProgram()

if __name__ == '__main__':
    main()

