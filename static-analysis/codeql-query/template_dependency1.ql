
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

predicate sameStructField(Expr assign, Expr check) {
  exists(PointerFieldAccess pfa1 | assign = pfa1)
  and
  exists(PointerFieldAccess pfa2 | check = pfa2)
  and
  assign.toString() = check.toString()
}

from EnumConstantAccess eca,
     EnumConstantAccess eca2,
     IfStmt ifs,
     NEExpr nee,
     AssignExpr ae,
     Function f1,
     Function f2
   where 
       (
        ( 
          f1.calls*(ae.getEnclosingFunction())
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
            f2.calls*(ifs.getEnclosingFunction())
            and
            isValidEntrypoint(f2)
          )
        )
	      and
        isErrorPathGuard(ifs)
        and
        (
          ae.getRValue() = eca2
        )
        and
        eca.getTarget() = eca2.getTarget()
        and
        eca2.toString() = eca.toString()
        and
        sameStructField(ae.getLValue(), nee.getLeftOperand())
        and
        f2.getName() != f1.getName()          
       )
select ifs.getEnclosingFunction(), f2.getName() + " | " + f1.getName() + " | " + eca2.getValue() + " | " + eca2.toString()  + " | " + ifs.getLocation().getFile().toString() + " | " + ifs.getLocation().getStartLine().toString() + " | " + ae.getLocation().getFile().toString() + " | " + ae.getLocation().getStartLine().toString()