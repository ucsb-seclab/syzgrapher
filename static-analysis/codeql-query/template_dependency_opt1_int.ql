predicate relevantStatementRec(Stmt s, ValidOpts a) {
  a.checkCase(s.(SwitchCase))
    or
    (
      not s instanceof SwitchCase
      and
      exists(SwitchStmt sws, BlockStmt bs |
        sws.getStmt() = bs 
        and
        bs.getAStmt() = s
        and
        relevantStatementRec(bs.getStmt(bs.getIndexOfStmt(s)-1), a)
      )
    )
}

predicate relevantStatement(Stmt s, ValidOpts a) {
  exists(Function f |
    checkEntryFunction(f)
    and
    callsNoSwitch*(f, s.getEnclosingFunction())
  )
  and
  relevantStatementRec(s, a)
}

int getDir(SwitchCase sc) {
  result = sc.getExpr().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(LShiftExpr).getLeftOperand().(Literal).getValue().toInt()
  or
  result = sc.getExpr().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(LShiftExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(Literal).getValue().toInt() +
  sc.getExpr().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(LShiftExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue().toInt()
}

int getType(SwitchCase sc) {
  result = sc.getExpr().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(LShiftExpr).getLeftOperand().(Literal).getValue().toInt()
}

int getNR(SwitchCase sc) {
  result = sc.getExpr().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(LShiftExpr).getLeftOperand().(Literal).getValue().toInt()
}

predicate fcReachableFromStmtFast(FunctionCall fc, ValidOpts a) {
  exists(Stmt s |
    s.getAChild*() = fc.getEnclosingStmt*()
    and
    relevantStatement(s, a)
  )
}
predicate fcIndirectReachableFromStmtFast(FunctionCall fc, ValidOpts a) {
  exists(FunctionCall fc2 |
    not fc2.getEnclosingStmt*().getAChild*() = fc.getEnclosingStmt*()
    and
    myCalls*(fc2.getTarget(), fc.getEnclosingFunction()) 
    and  
    relevantStatement(fc2.getEnclosingStmt*(), a)
  )
}

predicate fcReachableFromRelevantStatementFast(FunctionCall fc, ValidOpts a) {
  fcReachableFromStmtFast(fc, a)
  or
  fcIndirectReachableFromStmtFast(fc, a)
}

predicate isErrorPathGuard(IfStmt ifs) {
  ifs.getEnclosingFunction().getType().getName() != "void"
  and
  (
    exists(BreakStmt bs | ifs.getThen() = bs and bs.getBasicBlock().length() = 1) // break; not sure we want to check for length here
    or
    exists(GotoStmt gs | ifs.getThen() = gs) // goto err
    or
    exists(BlockStmt bs, ExprStmt es, AssignExpr ae, VariableAccess va, UnaryMinusExpr ume |
      ifs.getThen() = bs
      and
      bs.getStmt(0) = es // TODO we could generalize this to any statement in the block
      and
      es.getExpr() = ae
      and
      ae.getLValue() = va
      and
      ae.getRValue() = ume
    ) // err = - EXXX
    or
    exists(ReturnStmt rs, UnaryMinusExpr ume | 
      ifs.getThen() = rs
      and
      rs.getExpr() = ume) // return - EXX
  )
}

predicate memoryOperation(Function f){
  f.getName() = [
    "kmalloc", "kzalloc", "kcalloc", "kvmalloc_node",
    "kmalloc_node", "vmalloc", "vmalloc_node", "__kmalloc",
    "__vmalloc_node", "kmalloc_array", "__vmalloc_node_range",
    "__kmalloc_node", "krealloc_array", "kzalloc_node",
    "krealloc", "vmalloc_huge", "vzalloc", "vmalloc_user",
    "vzalloc_node", "vmalloc_32", "vmalloc_32_user",
    "kcalloc_node", "kmalloc_array_node", "__vmalloc",
    "kvzalloc", "kvmalloc", "kvmalloc_array", "kvcalloc",
    "kvzalloc_node", "kvcalloc_node",
    "kmem_cache_alloc", "kmem_cache_alloc_node",
    "kmem_cache_zalloc", "allocate_mm",
    "malloc", "calloc","alloc_pages"
  ]
  or
  f.getName().matches("%alloc%")
  or
  f.getName() = [
    "kfree", "kvfree", "vfree", "kfree_sensitive",
    "kmem_cache_free","kfree_const","kvfree_call_rcu",
    "kfree_skb","free_pages"
    // "__kasan_slab_free"
  ]
  or
  f.getName().matches("%kfree%")
}

predicate callsNoSwitch(Function fr, Function to) {
  exists(Expr exp |
    not exp.getParent*() instanceof SwitchStmt
    and
    fr.calls(to, exp)
  )
}

predicate myCalls(Function f1, Function f2) {
  not memoryOperation(f2)
  and
  f1.calls(f2)
}

predicate matchLeftSidesLight(NEExpr nee, FunctionCall fc, PointerFieldAccess pfa1) {
  pfa1.getEnclosingFunction() = fc.getTarget()
  and
  exists(PointerFieldAccess pfa2, AssignExpr ae |
    nee.getLeftOperand() = pfa2
    and
    ae.getEnclosingFunction() = fc.getTarget()
    and
    ae.getLValue() = pfa1
    and
    pfa1.getTarget() = pfa2.getTarget()
    )
}

from FunctionCall fc,
    Literal l1,
    Literal l2,
    IfStmt ifs,
    NEExpr nee,
    Function f2,
    ValidOpts va,
    PointerFieldAccess pfa,
    Struct s
  where
  (
    l1.getValue() = l2.getValue()
    and
    fc.getNumberOfArguments() = 2
    and
    fc.getAnArgument() = l2
    and
    nee.getParent*() = ifs
    and
    nee.getRightOperand() = l1
    and
    s.getAField() = pfa.getTarget()
    and
    isValidEntrypoint(f2)
    and
    isErrorPathGuard(ifs)
    and
    matchLeftSidesLight(nee, fc, pfa) 
    and
    fcReachableFromRelevantStatementFast(fc, va)
    and
    myCalls*(f2, ifs.getEnclosingFunction())  
  )
select ifs.getLocation(), f2.getName() + " | "  + l2.getValue() + " | " + (s.getName() + ":" + pfa.getTarget().getName()) + " | " + va.getvalue().toString() + " | " + ifs.getLocation().getFile().toString() + " | " + ifs.getLocation().getStartLine().toString() + " | " + fc.getLocation().getFile().toString() + " | " + fc.getLocation().getStartLine().toString()