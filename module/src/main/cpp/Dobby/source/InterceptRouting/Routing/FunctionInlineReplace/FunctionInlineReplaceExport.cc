#include "dobby_internal.h"

#include "Interceptor.h"
#include "InterceptRouting/InterceptRouting.h"
#include "InterceptRouting/Routing/FunctionInlineReplace/function-inline-replace.h"

PUBLIC int DobbyHook(void *address, void *replace_call, void **origin_call) {
  if (!address) {
    ERROR_LOG("function address is 0x0");
    return RS_FAILED;
  }

  DLOG(2, "[DobbyHook] Initialize at %p", address);

  // check if already hooked
  HookEntry *entry = Interceptor::SharedInstance()->FindHookEntry(address);

  DLOG(2, "[DobbyHook] Initialize at 2");
  if (entry) {
    DLOG(2, "[DobbyHook] Initialize at 21");
    FunctionInlineReplaceRouting *route = (FunctionInlineReplaceRouting *)entry->route;
    DLOG(2, "[DobbyHook] Initialize at 23");
    if (route->GetTrampolineTarget() == replace_call) {
      ERROR_LOG("function %p already been hooked.", address);
      return RS_FAILED;
    }
    DLOG(2, "[DobbyHook] Initialize at 63");
  }

  entry = new HookEntry();
  DLOG(2, "[DobbyHook] Initialize at 5");
  entry->id = Interceptor::SharedInstance()->GetHookEntryCount();
  entry->type = kFunctionInlineHook;
  entry->function_address = address;

  DLOG(2, "[DobbyHook] Initialize at 6");
  FunctionInlineReplaceRouting *route = new FunctionInlineReplaceRouting(entry, replace_call);
  DLOG(2, "[DobbyHook] Initialize at 7");
  route->Prepare();
  DLOG(2, "[DobbyHook] Initialize at 8");
  route->DispatchRouting();

  DLOG(2, "[DobbyHook] Initialize at 3");
  Interceptor::SharedInstance()->AddHookEntry(entry);

  // set origin call with relocated function
  *origin_call = entry->relocated_origin_function;
  DLOG(2, "[DobbyHook] Initialize at 4");
  // code patch & hijack original control flow entry
  route->Commit();
  DLOG(2, "[DobbyHook] Initialize at 55");
  return RS_SUCCESS;
}
