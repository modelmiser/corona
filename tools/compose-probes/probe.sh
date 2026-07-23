#!/usr/bin/env bash
# probe.sh — run the composition reactions and their pinned rejections.
#
# `WAREHOUSE-AND-LENS.md` scores a proposed composition on three questions; the first,
# "does it compile through the public API?", has a machine that answers it. This hands each
# reaction to that machine, and each rejection too — asserting BOTH that the negative fails
# and that it fails with the documented error code.
set -uo pipefail
cd "$(dirname "$0")"
fails=0

echo "── reactions (must compile and run) ──"
for b in a_unit_x_accuracy b_dp_x_crdt c_translog_x_lamport \
         d_swap_x_ecash e_arq_x_erasure f_consttime_x_threshold \
         g_bloom_x_accumulator h_sigma_x_commit; do
  if out=$(cargo run --quiet --bin "$b" 2>&1); then
    printf '  ok    %s\n' "$b"
    printf '%s\n' "$out" | sed 's/^/          /'
  else
    printf '  FAIL  %s\n%s\n' "$b" "$out"
    fails=$((fails + 1))
  fi
done

echo
echo "── rejections (must NOT compile, and must fail with THIS code) ──"
check_fail() {
  local bin=$1 code=$2 out
  out=$(cargo build --quiet --features negatives --bin "$bin" 2>&1)
  if [ $? -eq 0 ]; then
    printf '  FAIL  %-40s compiled, but must not\n' "$bin"
    fails=$((fails + 1))
  elif printf '%s' "$out" | grep -q "error\[$code\]"; then
    printf '  ok    %-40s %s\n' "$bin" "$code"
  else
    printf '  FAIL  %-40s expected %s, got: %s\n' "$bin" "$code" \
      "$(printf '%s' "$out" | grep -oE 'error\[E[0-9]+\]' | head -1)"
    fails=$((fails + 1))
  fi
}
check_fail fail_a_carrier_is_not_a_parameter E0308
check_fail fail_b_budget_does_not_replicate  E0599
check_fail fail_c_one_key_one_checkpoint     E0382
check_fail fail_d_no_leaf_is_generic_in_the_traded_item   E0308
check_fail fail_e_delivery_witness_is_sealed              E0451
check_fail fail_f_two_secrets_do_not_meet                 E0308
check_fail fail_g_absence_is_not_inclusion                E0308
check_fail fail_h_two_commitments_collide_by_name_only    E0308

echo
[ "$fails" -eq 0 ] && echo "probes green" || { echo "FAILED: $fails"; exit 1; }
