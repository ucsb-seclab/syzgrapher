
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
      bs.getStmt(0) = es
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
    // "__kasan_slab_free", "kmem_cache_free",
  ]
  or
  f.getName().matches("%kfree%")
}

predicate myCalls(Function f1, Function f2) {
  f1.calls(f2)
  and
  not memoryOperation(f2)
}

from FunctionCall fc,
  EnumConstantAccess eca,
  EnumConstantAccess eca2,
  IfStmt ifs,
  NEExpr nee,
  Function f1,
  Function f2
where 
  (
    ( 
      myCalls*(f1, fc.getEnclosingFunction())
      //f1.calls*(fc.getEnclosingFunction())
      and
      isValidEntrypoint(f1)
    )
    and
    nee.getParent*() = ifs
    and
    nee.getRightOperand() = eca
    and
    (
      //isValidEntrypoint(ifs.getEnclosingFunction())
      //or
      (
        myCalls*(f2, ifs.getEnclosingFunction())
        //f2.calls*(ifs.getEnclosingFunction())
        and
        isValidEntrypoint(f2)
      )
    )
    and
    isErrorPathGuard(ifs)
    and
    (
      fc.getAnArgument() = eca2
      and
      fc.getNumberOfArguments() = [2]
    )
    and
    eca.getTarget() = eca2.getTarget()
    and
    eca2.toString() = eca.toString()
    and
    f2.getName() != f1.getName() 
  )
//select ifs.getEnclosingFunction(), ifs.getEnclosingFunction().getName() + " | " + f1.getName() + " | " + eca2.getValue()
select ifs.getEnclosingFunction(), f2.getName() + " | " + f1.getName() + " | " + eca2.getValue() + " | " + eca2.toString()  + " | " + ifs.getLocation().getFile().toString() + " | " + ifs.getLocation().getStartLine().toString() + " | " + fc.getLocation().getFile().toString() + " | " + fc.getLocation().getStartLine().toString()