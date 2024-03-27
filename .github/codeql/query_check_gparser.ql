/**
 * @name Ignore EOF Not Checked If Sanitized by gparser
 * @description Ignore the warning about EOF not being checked if the data has been sanitized by the gparser function.
 */

 import cpp

 // Define a predicate to identify calls to scanf
 predicate scanfCall(Call c) {
   exists(
     FunctionCall fc |
       c = fc.getACall() and
       fc.getTarget().hasName("scanf")
   )
 }
 
 // Define a predicate to identify calls to the gparser function
 predicate gparserCall(Call c) {
   exists(
     FunctionCall fc |
       c = fc.getACall() and
       fc.getTarget().hasName("gparser")
   )
 }
 
 // Define a predicate to identify data flows from gparser to scanf
 predicate sanitizedByGparser(DataFlow::Node source, DataFlow::Node sink) {
   exists(DataFlow::Path path |
     path = DataFlow::pathBetween(source, sink) and
     path.getElements().noEmpty() and
     path.getElements().getFirst().getAParameter() = gparserCall.getAnArgument() and
     path.getElements().getLast().getAParameter() = scanfCall.getAnArgument()
   )
 }
 
 from
   DataFlow::Node source,
   DataFlow::Node sink,
   Call scanfCall,
   Call gparserCall
 where
   scanfCall(scanfCall) and
   gparserCall(gparserCall) and
   sanitizedByGparser(gparserCall, scanfCall)
 select scanfCall, "Data is sanitized by gparser before being used with scanf"