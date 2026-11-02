#pragma once
namespace ohno {
// A stable baseline (including a newly cloned/unapproved device) may enroll
// without policy. A probationary update must actually apply a valid online or
// cached policy before it can replace last-good. API/filter failures veto proof.
inline bool agent_cycle_healthy(bool trial,bool policy_applied,bool local_cycle_ok,bool request_pipe,bool wfp_cycle_ok){
    return (!trial||policy_applied)&&local_cycle_ok&&request_pipe&&wfp_cycle_ok;
}
}
